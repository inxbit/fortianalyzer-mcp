"""The v2 envelope: mint, shape gate, open (#40).

``<marker>-<kid>-<ct>-<tag>``. The tag primitive is specified separately in
``test_fpe_v2_tag.py``; this file covers the envelope around it.

Three decisions from #40 are pinned here, each by the property it was taken
for rather than by its spelling:

* **shape gate** -- a token that looks like v2 is committed to v2 and never
  falls back to v1, so forgery refusal holds from day one.
* **colon-free payloads** -- IPv6 and MAC ciphertexts are hex, which is what
  makes a v2 token usable as a URL host and invisible to the free-text MAC
  scan.
* **serial** as its own type, so it has an envelope at all.

The suffix-marked types (``domain``, ``email_local``) carry their own
envelope, spelled as dotted labels rather than hyphenated fields.
and are out of scope here; see ``TestWhatIsNotCoveredYet``.
"""

import logging
import re
from urllib.parse import urlsplit

import pytest

from fortianalyzer_mcp.masking.fpe_engine import (
    V2_MARKERS,
    FPEEngine,
    MaskingError,
)
from fortianalyzer_mcp.masking.wrapper import _MAC_RE, _TOKEN_PREFIX_SHAPE_RE

KEY = "2DE79D232DF5585D68CE47882AE256D6"
OTHER_KEY = "00112233445566778899AABBCCDDEEFF"


@pytest.fixture
def engine() -> FPEEngine:
    return FPEEngine(KEY)


def _ct(token: str) -> str:
    """Ciphertext out of a v1 ``<marker>-<kid>-<ct>`` token.

    Splits from the LEFT with maxsplit=2, because a ciphertext legitimately
    contains hyphens. Doing this from the right silently truncates a serial
    or hostname payload, which is the same hazard the envelope parser has to
    survive and which ``test_a_hyphenated_payload_parses`` covers.
    """
    return token.split("-", 2)[2]


def _all_types(engine: FPEEngine) -> list[tuple[str, str, str]]:
    """(vtype, v1 ciphertext, original value) for every enveloped type."""
    return [
        ("ipv4", engine.mask_ip("192.0.2.9"), "192.0.2.9"),
        ("ipv6", engine.mask_ip("2001:db8::5"), "2001:db8::5"),
        ("mac", engine.mask_mac("54:01:81:74:f5:ef"), "54:01:81:74:f5:ef"),
        ("serial", _ct(engine.mask_serial("FGT60FTK20000001")), "FGT60FTK20000001"),
        ("hostname", _ct(engine.mask_hostname("fw-hq-01")), "fw-hq-01"),
        ("username", _ct(engine.mask_username("Admin")), "Admin"),
        ("url_tail", _ct(engine.mask_url_tail("/a/b?c=1")), "/a/b?c=1"),
    ]


class TestRoundTrip:
    def test_every_type_round_trips(self, engine: FPEEngine):
        for vtype, ct, original in _all_types(engine):
            token = engine.v2_token(vtype, ct)
            assert engine.v2_open(token) == original, vtype

    def test_a_hyphenated_payload_parses(self, engine: FPEEngine):
        # A serial ciphertext reliably contains a hyphen, so this is the case
        # that fails if anyone splits the token from the right.
        #
        # It does NOT fail if the payload group is made lazy, and that is not
        # a gap in this test: measured, the lazy and greedy patterns agree on
        # every input, because the $ anchor plus the fixed-width tag group
        # pins the boundary. The equivalent mutant is noted at the pattern.
        ct = _ct(engine.mask_serial("FGT60FTK20000001"))
        assert "-" in ct, "fixture no longer exercises the hyphen case"

        assert engine.v2_open(engine.v2_token("serial", ct)) == "FGT60FTK20000001"

    def test_a_recased_token_still_opens(self, engine: FPEEngine):
        # Every payload but username is lowercase by construction, so folding
        # tolerates a model title-casing a token in prose.
        for vtype, ct, original in _all_types(engine):
            if vtype == "username":
                continue
            assert engine.v2_open(engine.v2_token(vtype, ct).upper()) == original, vtype

    def test_a_username_payload_keeps_its_case(self, engine: FPEEngine):
        # Admin and admin can be different principals, so the username
        # payload is the one that must NOT fold. Re-casing the whole token
        # corrupts it, and it is refused rather than opened as someone else.
        token = engine.v2_token("username", _ct(engine.mask_username("Admin")))

        assert engine.v2_open(token) == "Admin"
        with pytest.raises(MaskingError):
            engine.v2_open(token.upper())


class TestForgeryIsRefused:
    def test_a_flipped_tag_is_refused(self, engine: FPEEngine):
        token = engine.v2_token("hostname", _ct(engine.mask_hostname("fw-hq-01")))
        forged = token[:-1] + ("0" if token[-1] != "0" else "1")

        with pytest.raises(MaskingError, match="forged or corrupted"):
            engine.v2_open(forged)

    def test_a_tag_from_another_key_is_refused(self, engine: FPEEngine):
        ct = _ct(engine.mask_hostname("fw-hq-01"))
        # Same key id, so the kid check passes and the tag is what refuses.
        other = FPEEngine(OTHER_KEY)
        token = f"host-{engine.key_id}-{ct}-{other.v2_tag('hostname', ct)}"

        with pytest.raises(MaskingError, match="forged or corrupted"):
            engine.v2_open(token)

    def test_a_token_lifted_to_another_type_is_refused(self, engine: FPEEngine):
        # The tag is domain-separated per type, so a hostname payload
        # re-labelled as a serial does not authenticate.
        ct = _ct(engine.mask_hostname("fw-hq-01"))
        token = f"sn-{engine.key_id}-{ct}-{engine.v2_tag('hostname', ct)}"

        with pytest.raises(MaskingError, match="forged or corrupted"):
            engine.v2_open(token)

    def test_a_failed_verification_is_logged(self, engine: FPEEngine, caplog):
        # The 32-bit tag is only defensible while a forgery grind is visible:
        # one call can carry thousands of tokens, so 2**31 verifications is
        # on the order of 10**5 calls, not 10**9. This log line is the signal
        # an operator alarms on.
        token = engine.v2_token("hostname", _ct(engine.mask_hostname("fw-hq-01")))
        forged = token[:-1] + ("0" if token[-1] != "0" else "1")

        with caplog.at_level("WARNING"):
            with pytest.raises(MaskingError):
                engine.v2_open(forged)

        assert "failed tag verification" in caplog.text
        # The token itself is attacker-influenced text and must not be logged.
        assert forged not in caplog.text


class TestTheShapeGate:
    def test_a_v2_token_is_shaped_and_a_v1_token_is_not(self, engine: FPEEngine):
        assert engine.is_v2_shaped(engine.v2_token("hostname", _ct(engine.mask_hostname("a-b"))))
        assert not engine.is_v2_shaped(engine.mask_hostname("a-b"))

    def test_the_hazard_the_gate_exists_for(self, engine: FPEEngine):
        # A v2 token with a flipped tag IS a byte-valid v1 token: the tag is
        # hex and a hyphen, both inside the v1 alphabet. So the v1 path
        # decrypts it happily, to plausible garbage. Measured here rather
        # than asserted, because it is the whole reason the gate exists.
        token = engine.v2_token("hostname", _ct(engine.mask_hostname("fw-hq-01")))
        forged = token[:-1] + ("0" if token[-1] != "0" else "1")

        v1_result = engine.unmask_hostname(forged)
        assert v1_result != "fw-hq-01"

        # The gate is what stops a caller reaching that. Anything v2-shaped
        # is committed to v2, and v2 refuses.
        assert engine.is_v2_shaped(forged)
        with pytest.raises(MaskingError):
            engine.v2_open(forged)

    def test_a_bare_name_is_not_v2_shaped(self, engine: FPEEngine):
        # The false-refusal cost is real but narrow. These are not shaped,
        # so they are never committed to v2.
        for ordinary in ("host-fw01", "sn-abc", "user-admin", "host-2a85-plainct"):
            assert not engine.is_v2_shaped(ordinary), ordinary

    def test_opening_something_unshaped_refuses_rather_than_guesses(self, engine: FPEEngine):
        with pytest.raises(MaskingError, match="not a v2 token"):
            engine.v2_open("host-fw01")


class TestColonFreePayloads:
    def test_no_token_contains_a_colon(self, engine: FPEEngine):
        for vtype, ct, _ in _all_types(engine):
            assert ":" not in engine.v2_token(vtype, ct), vtype

    def test_an_ipv6_token_works_as_a_url_host(self, engine: FPEEngine):
        # This is the measurement that drove the decision. With the address
        # spelling, urlsplit raised on CPython >= 3.11 and we require 3.12,
        # so a re-masked echo burned to an irreversible placeholder and an
        # inbound token went to the appliance as a literal.
        token = engine.v2_token("ipv6", engine.mask_ip("2001:db8::5"))

        assert urlsplit(f"https://{token}:8443/x").hostname == token.lower()

    def test_the_free_text_mac_scan_does_not_match_inside_a_mac_envelope(self, engine: FPEEngine):
        v2 = engine.v2_token("mac", engine.mask_mac("54:01:81:74:f5:ef"))

        assert _MAC_RE.search(v2) is None
        # Control: the regex still matches a v1 MAC token, so the assertion
        # above is about the hex spelling and not about a dead regex.
        assert _MAC_RE.search(engine.mask_mac("54:01:81:74:f5:ef")) is not None


class TestKeyId:
    def test_a_token_from_another_key_is_refused_on_the_key_id(self, engine: FPEEngine):
        # Asserting only "refused" cannot see the key-id check at all: the
        # tag key derives from the engine key, so a foreign token fails the
        # tag too and the test passes with the key-id check deleted.
        # Measured, before this assertion was tightened.
        #
        # Which one refuses matters. The key-id check says "rotated key",
        # which is diagnosable and ordinary. The tag failure says "forged or
        # corrupted" and fires the warning that is meant to be the only
        # signal separating a forgery grind from normal traffic. Letting a
        # key rotation trip that alarm poisons it.
        foreign = FPEEngine(OTHER_KEY)
        token = foreign.v2_token("hostname", _ct(foreign.mask_hostname("fw-hq-01")))

        with pytest.raises(MaskingError) as caught:
            engine.v2_open(token)

        assert "forged or corrupted" not in str(caught.value)

    def test_a_key_rotation_does_not_fire_the_forgery_alarm(self, engine: FPEEngine, caplog):
        foreign = FPEEngine(OTHER_KEY)
        token = foreign.v2_token("hostname", _ct(foreign.mask_hostname("fw-hq-01")))

        with caplog.at_level("WARNING"):
            with pytest.raises(MaskingError):
                engine.v2_open(token)

        assert "failed tag verification" not in caplog.text


class TestTheTwoEnvelopesAreDistinct:
    def test_the_suffix_marked_types_have_their_own_envelope(self, engine: FPEEngine):
        # domain and email_local are marked by a dotted suffix rather than a
        # hyphenated prefix, because a domain token has to keep parsing as a
        # domain: the email form embeds it as <local>@<domain-token>. So the
        # prefix envelope genuinely does not fit them, and they are absent
        # from V2_MARKERS and from v2_token on purpose.
        #
        # They are not unenveloped, though. This asserted that they were
        # while it was true; they now carry the tag as another dotted label
        # instead, through v2_suffix_token.
        assert "domain" not in V2_MARKERS
        assert "email_local" not in V2_MARKERS

        with pytest.raises(MaskingError, match="no v2 envelope"):
            engine.v2_token("domain", "abc")

        for vtype, value in (("domain", "example.com"), ("email_local", "a@example.com")):
            token = engine.mint(vtype, value)
            assert engine.is_v2_suffix_shaped(token)
            assert engine.v2_suffix_open(token) == value

    def test_a_prefix_type_is_refused_by_the_suffix_envelope(self, engine: FPEEngine):
        """The two envelopes do not accept each other's types."""
        with pytest.raises(MaskingError, match="no v2 suffix envelope"):
            engine.v2_suffix_token("hostname", "abc")

    def test_the_marker_set_matches_the_sibling_server(self):
        # These spellings already shipped in fortimanager-mcp's reserved
        # vocabulary (masking/tokens.py, PREFIX_MARKERS). A token minted here
        # has to be recognisable there, so the set is pinned rather than
        # left to drift.
        assert set(V2_MARKERS.values()) == {"ip4", "ip6", "mac", "sn", "url", "host", "user"}


class TestTheMutatingToolGateCoversEveryEnvelope:
    def test_the_shape_recogniser_knows_every_v2_marker(self, engine: FPEEngine):
        # _TOKEN_PREFIX_SHAPE_RE is what the mutating-tool gate (#108) uses
        # to tell a token from a legitimate value. ip4/ip6/mac had no marked
        # form before v2, so they were never in it, and the gate would have
        # gone on passing while covering none of the three types the envelope
        # exists to make detectable. That is the failure direction that does
        # not announce itself.
        for vtype, ct, _ in _all_types(engine):
            token = engine.v2_token(vtype, ct)
            assert _TOKEN_PREFIX_SHAPE_RE.match(token), vtype

    def test_it_still_does_not_flag_ordinary_values(self):
        # The markers are only half of it: a real value that merely starts
        # with one is not a token, because it has no 4-hex key id.
        for ordinary in ("ip4-lan", "mac-table", "sn-abc", "host-fw01"):
            assert not _TOKEN_PREFIX_SHAPE_RE.match(ordinary), ordinary


class TestSpecPin:
    def test_the_envelope_grammar_is_pinned(self, engine: FPEEngine):
        # A literal, because the grammar is the shared contract and a test
        # that rebuilds it from the implementation drifts with it.
        assert engine.v2_token("ipv4", "248.194.94.248") == "ip4-2a85-248.194.94.248-53eecc82"

        # An IPv6 token whose ciphertext has a LEADING ZERO nibble, chosen on
        # purpose. The zero padding is part of the shared format and nothing
        # else pins its width: the tag literals in test_fpe_v2_tag.py are fed
        # hex directly and never cross _v2_payload_out, so dropping "032x"
        # for "x" round-trips against itself and passes the whole suite.
        # Measured. About one in sixteen ciphertexts starts with a zero, and
        # for those a port that dropped the padding would mint tokens the
        # other server refuses and logs as forgeries.
        v6 = engine.v2_token("ipv6", engine.mask_ip("2001:db8::16"))
        assert v6 == "ip6-2a85-0a1baadc502f122e379b90efd546b435-93e5818b"
        assert len(v6.split("-")[2]) == 32

        # And the shape, stated independently of any one token.
        assert re.fullmatch(
            r"(?:ip4|ip6|mac|sn|url|host|user)-[0-9a-f]{4}-.+-[0-9a-f]{8}",
            engine.v2_token("hostname", _ct(engine.mask_hostname("fw-hq-01"))),
        )


class TestTheSuffixEnvelope:
    """The domain/email_local envelope: ``<ct>.<tag>.<kid>.<mask_suffix>``.

    Spelled as dotted labels rather than the prefix form's hyphenated
    fields so the token keeps parsing as a domain, which is what lets
    ``<local>@<domain-token>`` still read as an email.
    """

    @staticmethod
    def _parts(engine: FPEEngine, token: str) -> tuple[str, str, str]:
        """Split a suffix token into (ct, tag, kid).

        Not rsplit(".", 3): mask_suffix is itself dotted ("masked.invalid"),
        so counting from the right lands inside the marker.
        """
        payload = token[: -(len(engine.mask_suffix) + 1)]
        ct, tag, kid = payload.rsplit(".", 2)
        return ct, tag, kid

    @pytest.mark.parametrize(
        ("vtype", "value"),
        [("domain", "corp.example.com"), ("email_local", "alice@corp.example.com")],
    )
    def test_it_round_trips(self, engine: FPEEngine, vtype: str, value: str):
        assert engine.v2_suffix_open(engine.mint(vtype, value)) == value

    def test_a_domain_token_is_still_shaped_like_a_domain(self, engine: FPEEngine):
        token = engine.mint("domain", "corp.example.com")
        assert token.endswith("." + engine.mask_suffix)
        assert "@" not in token

    def test_an_email_token_is_still_shaped_like_an_email(self, engine: FPEEngine):
        token = engine.mint("email_local", "alice@corp.example.com")
        assert token.count("@") == 1
        assert token.endswith("." + engine.mask_suffix)

    @pytest.mark.parametrize("vtype", ["domain", "email_local"])
    def test_a_flipped_tag_is_refused(self, engine: FPEEngine, vtype: str):
        value = "corp.example.com" if vtype == "domain" else "alice@corp.example.com"
        ct, tag, kid = self._parts(engine, engine.mint(vtype, value))
        flipped = ("f" * len(tag)) if tag != "f" * len(tag) else ("0" * len(tag))

        with pytest.raises(MaskingError, match="tag mismatch"):
            engine.v2_suffix_open(f"{ct}.{flipped}.{kid}.{engine.mask_suffix}")

    def test_a_forged_token_is_not_retried_on_the_v1_path(self, engine: FPEEngine):
        """The commitment rule. A v2 suffix token is also a byte-valid v1
        one, so a fallback would decrypt a flipped tag to plausible garbage
        and forgery refusal would not hold at all."""
        ct, tag, kid = self._parts(engine, engine.mint("domain", "corp.example.com"))
        flipped = ("f" * len(tag)) if tag != "f" * len(tag) else ("0" * len(tag))

        with pytest.raises(MaskingError, match="tag mismatch"):
            engine.unmask_token(f"{ct}.{flipped}.{kid}.{engine.mask_suffix}")

    def test_a_foreign_key_id_is_refused(self, engine: FPEEngine):
        ct, tag, _ = self._parts(engine, engine.mint("domain", "corp.example.com"))
        foreign = f"{ct}.{tag}.ffff.{engine.mask_suffix}"

        with pytest.raises(MaskingError):
            engine.v2_suffix_open(foreign)

    def test_an_email_half_cannot_be_recombined(self, engine: FPEEngine):
        """The email tag covers ``<local_ct>@<domain_ct>`` as one payload,
        so a half lifted from another token does not verify."""
        a = engine.mint("email_local", "alice@corp.example.com")
        b = engine.mint("email_local", "bob@other.example.net")
        a_local = a.split("@")[0]
        b_rest = b.split("@")[1]

        with pytest.raises(MaskingError, match="tag mismatch"):
            engine.v2_suffix_open(f"{a_local}@{b_rest}")

    def test_a_domain_tag_does_not_verify_as_an_email(self, engine: FPEEngine):
        """Per-type domain separation, same property the prefix form has."""
        domain_ct = self._parts(engine, engine.mint("domain", "corp.example.com"))[0]
        assert engine.v2_tag("domain", domain_ct) != engine.v2_tag("email_local", domain_ct)

    def test_a_v1_token_is_not_mistaken_for_v2(self, engine: FPEEngine):
        assert not engine.is_v2_suffix_shaped(engine.mask_domain("corp.example.com"))
        assert not engine.is_v2_suffix_shaped(engine.mask_email("alice@corp.example.com"))

    def test_a_bare_name_is_not_mistaken_for_v2(self, engine: FPEEngine):
        for value in ("corp.example.com", "fw01", "", "."):
            assert not engine.is_v2_suffix_shaped(value)

    @pytest.mark.parametrize("vtype", ["domain", "email_local"])
    def test_the_primitive_route_also_commits_to_v2(self, engine: FPEEngine, vtype: str):
        """``unmask_token`` is not the only way in. The primitives are
        callable directly, and a v2 token is a byte-valid v1 one, so each
        route has to ask the shape question itself: dropping the check from
        either one alone leaves the other covering it, and the whole suite
        stays green."""
        value = "corp.example.com" if vtype == "domain" else "alice@corp.example.com"
        token = engine.mint(vtype, value)

        primitive = engine.unmask_domain if vtype == "domain" else engine.unmask_email
        assert primitive(token) == value

    @pytest.mark.parametrize("vtype", ["domain", "email_local"])
    def test_the_dispatch_route_also_commits_to_v2(self, engine: FPEEngine, vtype: str):
        """The other half of the pair above, through the route production
        uses: ArgUnmasker resolves a marked token via unmask_token."""
        value = "corp.example.com" if vtype == "domain" else "alice@corp.example.com"
        assert engine.unmask_token(engine.mint(vtype, value)) == value

    def test_a_v1_token_ending_in_a_non_hex_label_still_resolves(self, engine: FPEEngine):
        """The shape predicate checks the tag is hex, not merely that a
        label of the right width is there. Without that, a v1 token whose
        ciphertext happens to end in a dot and eight non-hex characters is
        committed to v2 and refused, when it is a perfectly good v1 token.
        """
        v1 = f"somect.abcdefgh.{engine.key_id}.{engine.mask_suffix}"
        assert not engine.is_v2_suffix_shaped(v1)

    def test_the_suffix_envelope_charges_the_verification_budget(self, engine: FPEEngine) -> None:
        """The budget bounds an attacker grinding tags on the inbound path.
        Unpinned on this envelope, removing the charge left the whole suite
        green, and this codebase has shipped a fail-silent budget before.

        The exhaustion is caught by type rather than by pytest.raises:
        VerificationBudgetExhausted subclasses MaskingError, so a plain
        raises(MaskingError) swallows the very thing under test.
        """
        from fortianalyzer_mcp.masking.fpe_engine import (
            V2_VERIFY_BUDGET,
            VerificationBudgetExhausted,
            begin_v2_verification_budget,
        )

        begin_v2_verification_budget()
        ct, tag, kid = self._parts(engine, engine.mint("domain", "corp.example.com"))
        bad = f"{ct}.{'f' * len(tag)}.{kid}.{engine.mask_suffix}"
        exhausted = False
        for _ in range(V2_VERIFY_BUDGET + 2):
            try:
                engine.v2_suffix_open(bad)
            except VerificationBudgetExhausted:
                exhausted = True
                break
            except MaskingError:
                continue
        begin_v2_verification_budget()
        assert exhausted, "the suffix envelope never charged the verification budget"

    def test_the_suffix_alarm_fires_once_not_per_failure(self, engine: FPEEngine, caplog) -> None:
        """`>=` fired on every failure from the eighth on, so the escalation
        meant to make a grind visible was itself the flood."""
        from fortianalyzer_mcp.masking.fpe_engine import begin_v2_verification_budget

        begin_v2_verification_budget()
        ct, tag, kid = self._parts(engine, engine.mint("domain", "corp.example.com"))
        bad = f"{ct}.{'f' * len(tag)}.{kid}.{engine.mask_suffix}"
        with caplog.at_level(logging.ERROR):
            for _ in range(12):
                with pytest.raises(MaskingError):
                    engine.v2_suffix_open(bad)
        assert sum("possible forgery attempt" in r.message for r in caplog.records) == 1
        begin_v2_verification_budget()

    def test_the_trailer_separator_is_required(self, engine: FPEEngine) -> None:
        """Without the leading dot of ``.<tag>.<kid>`` the predicate widens
        from a 1.6e-5 false refusal to 6.6e-4, for no gain."""
        assert not engine.is_v2_suffix_shaped(f"abcdeadbeef.{engine.key_id}.{engine.mask_suffix}")

    @pytest.mark.parametrize("vtype", ["domain", "email_local"])
    def test_our_own_suffix_token_is_recognised_as_ours(
        self, engine: FPEEngine, vtype: str
    ) -> None:
        """One predicate has to answer for both envelopes. Without this a
        suffix token echoed back into a typed field is re-masked into a
        double token, and one restore yields the inner token."""
        value = "corp.example.com" if vtype == "domain" else "alice@corp.example.com"
        assert engine.is_own_v2_token(engine.mint(vtype, value))

    def test_a_foreign_suffix_token_is_not_ours(self, engine: FPEEngine) -> None:
        other = FPEEngine("1" * 32)
        assert not engine.is_own_v2_token(other.mint("domain", "corp.example.com"))

    def test_a_real_domain_is_not_mistaken_for_ours(self, engine: FPEEngine) -> None:
        assert not engine.is_own_v2_token("corp.example.com")
