"""Tests for FortiAnalyzer DVM (Device Manager) tools."""

from typing import Any

import pytest

import fortianalyzer_mcp.tools.dvm_tools as dvm_tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.query.filters import FilterCondition


class TestDVMTools:
    """Tests for device management tools."""

    @pytest.fixture
    def mock_client_configured(
        self, mock_client: FortiAnalyzerClient, configure_mock_responses: None
    ) -> FortiAnalyzerClient:
        """Provide a mock client with configured responses."""
        return mock_client

    async def test_list_devices_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test list_devices returns device list."""
        result = await mock_client_configured.list_devices(adom="root")
        assert len(result) == 2
        assert result[0]["name"] == "FGT-01"
        assert result[0]["sn"] == "FGT60F0000000001"

    async def test_list_devices_with_fields(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test list_devices with field filter."""
        result = await mock_client_configured.list_devices(adom="root", fields=["name", "ip"])
        assert len(result) == 2

    async def test_get_device_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test get_device returns device details."""
        result = await mock_client_configured.get_device("FGT-01", adom="root")
        assert result["name"] == "FGT-01"

    async def test_list_device_vdoms_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test list_device_vdoms returns VDOMs."""
        result = await mock_client_configured.list_device_vdoms(device="FGT-01", adom="root")
        assert len(result) == 1
        assert result[0]["name"] == "root"

    async def test_list_device_groups_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test list_device_groups returns groups."""
        result = await mock_client_configured.list_device_groups(adom="root")
        assert len(result) == 1
        assert result[0]["name"] == "All_FortiGate"

    async def test_add_device_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test add_device creates device."""
        device = {
            "name": "FGT-NEW",
            "ip": "192.168.1.100",
            "adm_usr": "admin",
            "adm_pass": "password",
        }
        result = await mock_client_configured.add_device(adom="root", device=device)
        assert result is not None

    async def test_delete_device_success(self, mock_client_configured: FortiAnalyzerClient) -> None:
        """Test delete_device removes device."""
        result = await mock_client_configured.delete_device(adom="root", device="FGT-01")
        assert result is not None

    async def test_add_device_list_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test add_device_list adds multiple devices."""
        devices = [
            {"name": "FGT-A", "ip": "192.168.1.10"},
            {"name": "FGT-B", "ip": "192.168.1.11"},
        ]
        result = await mock_client_configured.add_device_list(adom="root", devices=devices)
        assert result is not None

    async def test_delete_device_list_success(
        self, mock_client_configured: FortiAnalyzerClient
    ) -> None:
        """Test delete_device_list removes multiple devices."""
        devices = [
            {"name": "FGT-A"},
            {"name": "FGT-B"},
        ]
        result = await mock_client_configured.delete_device_list(adom="root", devices=devices)
        assert result is not None


class TestSearchDevicesStructuredFilters:
    """filters compiles to the array dialect and composes with the old params."""

    class FakeClient:
        """Captures the filter and projection search_devices hands to the client."""

        def __init__(self) -> None:
            self.captured: list[list[Any]] | None = None
            self.captured_fields: list[str] | None = None

        async def list_devices(
            self,
            adom: str,
            filter: list[list[Any]] | None = None,
            fields: list[str] | None = None,
        ) -> list[dict[str, Any]]:
            self.captured = filter
            self.captured_fields = fields
            return []

    def _install(self, monkeypatch: pytest.MonkeyPatch) -> FakeClient:
        fake = self.FakeClient()
        monkeypatch.setattr(dvm_tools, "_get_client", lambda: fake)
        return fake

    async def test_filters_compile_to_array_entries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(
            filters=[FilterCondition(field="platform", op="contains", value="VM")]
        )

        assert fake.captured == [["platform_str", "like", "%VM%"]]

    async def test_enum_name_is_coerced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(
            filters=[FilterCondition(field="conn_status", op="eq", value="down")]
        )

        assert fake.captured == [["conn_status", "==", 2]]

    async def test_structured_and_narrow_params_are_anded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every narrow parameter and every structured condition lands in one
        "&&" chain. Measured on 7.6.7 (#146): the bare list for
        name_filter="myfw01" plus platform_filter="Syslog" returned both
        myfw01 devices *and* six syslog devices, where the answer was 0."""
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(
            name_filter="fgt",
            platform_filter="VM",
            os_version_filter="7.6",
            connection_status="up",
            filters=[FilterCondition(field="desc", op="contains", value="branch")],
        )

        assert fake.captured == [
            ["name", "like", "%fgt%"],
            "&&",
            ["platform_str", "like", "%VM%"],
            "&&",
            ["os_ver", "==", 7],
            "&&",
            ["mr", "==", 6],
            "&&",
            ["conn_status", "==", 1],
            "&&",
            ["desc", "like", "%branch%"],
        ]

    async def test_two_narrow_params_are_anded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = self._install(monkeypatch)

        result = await dvm_tools.search_devices(name_filter="myfw01", platform_filter="Syslog")

        expected = [["name", "like", "%myfw01%"], "&&", ["platform_str", "like", "%Syslog%"]]
        assert fake.captured == expected
        assert result["filter_applied"] == expected

    async def test_two_structured_conditions_are_anded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(
            filters=[
                FilterCondition(field="name", op="eq", value="myfw01"),
                FilterCondition(field="name", op="eq", value="myfw01-old"),
            ]
        )

        assert fake.captured == [["name", "==", "myfw01"], "&&", ["name", "==", "myfw01-old"]]

    async def test_not_in_is_anded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(
            filters=[FilterCondition(field="name", op="not_in", value=["myfw01", "myfw01-old"])]
        )

        assert fake.captured == [["name", "!=", "myfw01"], "&&", ["name", "!=", "myfw01-old"]]

    async def test_response_echoes_the_compiled_filter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An LLM caller can verify what was sent without live-data inference."""
        self._install(monkeypatch)

        result = await dvm_tools.search_devices(name_filter="fgt")

        assert result["filter_applied"] == [["name", "like", "%fgt%"]]

    async def test_no_filters_echo_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install(monkeypatch)

        result = await dvm_tools.search_devices()

        assert result["filter_applied"] is None

    async def test_fields_projection_is_forwarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """list_devices slims responses with fields=[...]; search_devices must too."""
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(fields=["name", "os_ver"])

        assert fake.captured_fields == ["name", "os_ver"]

    async def test_validation_error_returns_the_standard_envelope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Error handlers normalised on the query_logs contract must not crash here."""
        self._install(monkeypatch)

        result = await dvm_tools.search_devices(
            filters=[FilterCondition(field="bogus", op="eq", value="x")]
        )

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert result["operation"] == "search_devices"
        assert result["retry_count"] == 0

    async def test_unknown_device_field_is_rejected_locally(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The field set is enumerable, so this never reaches the appliance."""

        class Unreachable:
            async def list_devices(self, **kwargs: Any) -> list[dict[str, Any]]:
                raise AssertionError("must not reach the API")

        monkeypatch.setattr(dvm_tools, "_get_client", lambda: Unreachable())

        result = await dvm_tools.search_devices(
            filters=[FilterCondition(field="not_a_field", op="eq", value="x")]
        )

        assert result["status"] == "error"
        assert "conn_status" in result["message"]


class TestSearchDevicesOsVersion:
    """os_version_filter splits "major[.minor[.patch]]" into integer equality.

    dvmdb stores the version across three integers, ``os_ver`` (7), ``mr`` (6)
    and ``patch`` (7), and ``like`` does not text-match an integer: measured on
    7.6.7 (#146), the old ``os_ver like "%7%"`` returned seven devices, all with
    ``os_ver=0``, and none of the four on 7.
    """

    class Unreachable:
        async def list_devices(self, **kwargs: Any) -> list[dict[str, Any]]:
            raise AssertionError("must not reach the API")

    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            ("7", [["os_ver", "==", 7]]),
            ("7.6", [["os_ver", "==", 7], "&&", ["mr", "==", 6]]),
            (
                "v7.6.7",
                [["os_ver", "==", 7], "&&", ["mr", "==", 6], "&&", ["patch", "==", 7]],
            ),
            (" 7.4 ", [["os_ver", "==", 7], "&&", ["mr", "==", 4]]),
        ],
    )
    async def test_version_splits_into_integer_fields(
        self, version: str, expected: list[Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = TestSearchDevicesStructuredFilters.FakeClient()
        monkeypatch.setattr(dvm_tools, "_get_client", lambda: fake)

        result = await dvm_tools.search_devices(os_version_filter=version)

        assert result["status"] == "success"
        assert fake.captured == expected

    @pytest.mark.parametrize("version", ["7.x", "7.6.7.1", " ", "seven", "7..6", "7.", "-7"])
    async def test_malformed_version_is_refused_before_any_request(
        self, version: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(dvm_tools, "_get_client", lambda: self.Unreachable())

        result = await dvm_tools.search_devices(os_version_filter=version)

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert "Invalid os_version_filter" in result["message"]

    # Superscript two, and Arabic-Indic seven and six.
    @pytest.mark.parametrize("version", ["²", "7.²", "٧.٦"])
    async def test_non_ascii_digits_are_refused_by_the_validator(
        self, version: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``str.isdigit`` accepts all three: the superscript then fails in
        ``int()``, and the Arabic-Indic digits are read as 7.6."""
        monkeypatch.setattr(dvm_tools, "_get_client", lambda: self.Unreachable())

        result = await dvm_tools.search_devices(os_version_filter=version)

        assert result["status"] == "error"
        assert result["error"] == "validation_error"
        assert "Invalid os_version_filter" in result["message"]


class TestSearchDevicesProjection:
    """Device projection is native: the field list goes to dvmdb."""

    class FakeClient:
        def __init__(self) -> None:
            self.captured_fields: list[str] | None = None

        async def list_devices(
            self,
            adom: str,
            filter: list[list[Any]] | None = None,
            fields: list[str] | None = None,
        ) -> list[dict[str, Any]]:
            self.captured_fields = fields
            return [{"name": "fgt-01", "ip": "10.0.0.1"}]

    def _install(self, monkeypatch: pytest.MonkeyPatch) -> FakeClient:
        fake = self.FakeClient()
        monkeypatch.setattr(dvm_tools, "_get_client", lambda: fake)
        return fake

    async def test_default_sends_the_curated_field_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices()

        assert fake.captured_fields is not None
        assert "name" in fake.captured_fields
        assert "sn" in fake.captured_fields, "join key must survive"
        assert "adm_usr" not in fake.captured_fields

    async def test_star_sends_no_field_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """["*"] means the appliance default, which is every field."""
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(fields=["*"])

        assert fake.captured_fields is None

    async def test_alias_is_resolved_before_sending(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = self._install(monkeypatch)

        await dvm_tools.search_devices(fields=["serial_number", "os_version"])

        assert fake.captured_fields is not None
        assert sorted(fake.captured_fields) == ["os_ver", "sn"]

    async def test_a_field_outside_the_curated_set_is_forwarded_with_a_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``oid`` is a real dvmdb key -- this tool's own docstring says so.

        The 16-name device set is a filter boundary, not a catalogue of what a
        dvmdb device object carries (the appliance defines roughly sixty). When
        the projection path enforced it, ``fields=["oid"]`` -- along with
        ``ha_mode``, ``os_type``, ``last_checked`` and ``devvds`` -- became a
        ValidationError, though every one of them was readable before this
        parameter existed.
        """
        fake = self._install(monkeypatch)

        result = await dvm_tools.search_devices(fields=["name", "oid", "ha_mode"])

        assert result["status"] == "success"
        assert fake.captured_fields == ["ha_mode", "name", "oid"]
        assert len(result["warnings"]) == 2
        assert any("oid" in w for w in result["warnings"])

    async def test_a_malformed_field_name_is_still_rejected_locally(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Permissive is not unguarded; the shape check still fails closed."""

        class Unreachable:
            async def list_devices(self, **kwargs: Any) -> list[dict[str, Any]]:
                raise AssertionError("must not reach the API")

        monkeypatch.setattr(dvm_tools, "_get_client", lambda: Unreachable())

        result = await dvm_tools.search_devices(fields=['name" or 1=1'])

        assert result["status"] == "error"

    async def test_an_unknown_filter_field_is_still_rejected_locally(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The filter path keeps its strict set; only projection loosened."""

        class Unreachable:
            async def list_devices(self, **kwargs: Any) -> list[dict[str, Any]]:
                raise AssertionError("must not reach the API")

        monkeypatch.setattr(dvm_tools, "_get_client", lambda: Unreachable())

        result = await dvm_tools.search_devices(
            filters=[FilterCondition(field="not_a_field", op="eq", value="x")]
        )

        assert result["status"] == "error"
        assert "conn_status" in result["message"]
