"""Regression tests for tool-level bugs found during QA.

Each fake client mirrors the real ``FortiAnalyzerClient`` method signature so a
tool passing a wrong keyword argument fails the test (a plain MagicMock would
silently accept anything).
"""

from __future__ import annotations

from typing import Any

import pytest

import fortianalyzer_mcp.tools.dvm_tools as dvm_tools
import fortianalyzer_mcp.tools.fortiview_tools as fortiview_tools
import fortianalyzer_mcp.tools.incident_tools as incident_tools
import fortianalyzer_mcp.tools.ioc_tools as ioc_tools
import fortianalyzer_mcp.tools.report_tools as report_tools
import fortianalyzer_mcp.tools.system_tools as system_tools
from fortianalyzer_mcp.utils.validation import MASK_VALUE

CUSTOM_RANGE = "2024-01-01 00:00:00|2024-01-02 00:00:00"

DEVICE_WITH_CREDS = {
    "name": "FGT-01",
    "ip": "192.168.1.1",
    "sn": "FGT60F0000000001",
    "conn_status": 1,
    "adm_usr": "admin",
    "adm_pass": ["ENC", "SH2MPbdXdoo7ekXsbtjm0Ga"],
}


class TestAcknowledgeIocEventsKwarg:
    """Regression: tool passed ``ioc_ids=`` but the client expects ``event_ids=``."""

    async def test_tool_calls_client_with_event_ids(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[tuple[str, list[str], str]] = []

        class FakeClient:
            async def acknowledge_ioc_events(
                self, adom: str, event_ids: list[str], user: str
            ) -> dict[str, Any]:
                calls.append((adom, event_ids, user))
                return {"status": "ok"}

        monkeypatch.setattr(ioc_tools, "get_faz_client", lambda: FakeClient())

        result = await ioc_tools.acknowledge_ioc_events(
            ioc_ids=["IOC-001", "IOC-002"], user="analyst1", adom="root"
        )

        assert result["status"] == "success"
        assert result["acknowledged_count"] == 2
        assert calls == [("root", ["IOC-001", "IOC-002"], "analyst1")]


class TestFortiviewPollsToCompletion:
    """Regression: get_fortiview_data returned partial data when percentage < 100."""

    async def test_partial_data_is_not_returned_early(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.fetches = 0

            async def fortiview_run(self, **kwargs: Any) -> dict[str, Any]:
                return {"tid": 99}

            async def fortiview_fetch(self, **kwargs: Any) -> dict[str, Any]:
                self.fetches += 1
                if self.fetches == 1:
                    # Partial result: non-empty data but the scan is incomplete.
                    return {"percentage": 50, "data": [{"srcip": "10.0.0.1"}]}
                return {
                    "percentage": 100,
                    "data": [{"srcip": "10.0.0.1"}, {"srcip": "10.0.0.2"}],
                }

        fake = FakeClient()
        monkeypatch.setattr(fortiview_tools, "get_faz_client", lambda: fake)

        result = await fortiview_tools.get_fortiview_data(
            view_name="top-sources", adom="root", time_range=CUSTOM_RANGE
        )

        assert result["status"] == "success"
        assert fake.fetches == 2, "must keep polling past a partial (<100%) fetch"
        assert result["count"] == 2

    async def test_missing_percentage_defaults_to_complete(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def fortiview_run(self, **kwargs: Any) -> dict[str, Any]:
                return {"tid": 7}

            async def fortiview_fetch(self, **kwargs: Any) -> dict[str, Any]:
                return {"data": [{"srcip": "10.0.0.1"}]}

        monkeypatch.setattr(fortiview_tools, "get_faz_client", lambda: FakeClient())

        result = await fortiview_tools.get_fortiview_data(
            view_name="top-sources", adom="root", time_range=CUSTOM_RANGE
        )

        assert result["status"] == "success"
        assert result["count"] == 1


class TestDeviceCredentialSanitization:
    """Regression: device tools returned raw DVMDB objects including adm_pass."""

    async def test_system_list_devices_masks_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def list_devices(
                self, adom: str, fields: list[str] | None = None
            ) -> list[dict[str, Any]]:
                return [dict(DEVICE_WITH_CREDS)]

        monkeypatch.setattr(system_tools, "get_faz_client", lambda: FakeClient())

        result = await system_tools.list_devices(adom="root")

        assert result["status"] == "success"
        device = result["devices"][0]
        assert device["adm_pass"] == MASK_VALUE
        assert device["name"] == "FGT-01"
        assert device["ip"] == "192.168.1.1"

    async def test_system_get_device_masks_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def get_device(self, name: str, adom: str, loadsub: int = 0) -> dict[str, Any]:
                return dict(DEVICE_WITH_CREDS)

        monkeypatch.setattr(system_tools, "get_faz_client", lambda: FakeClient())

        result = await system_tools.get_device(name="FGT-01", adom="root")

        assert result["status"] == "success"
        assert result["device"]["adm_pass"] == MASK_VALUE

    async def test_dvm_search_devices_masks_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def list_devices(
                self, adom: str, filter: list[Any] | None = None
            ) -> list[dict[str, Any]]:
                return [dict(DEVICE_WITH_CREDS)]

        monkeypatch.setattr(dvm_tools, "get_faz_client", lambda: FakeClient())

        result = await dvm_tools.search_devices(adom="root", name_filter="FGT")

        assert result["status"] == "success"
        assert result["devices"][0]["adm_pass"] == MASK_VALUE

    async def test_dvm_get_device_info_masks_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def get_device(self, device: str, adom: str, loadsub: int = 0) -> dict[str, Any]:
                return dict(DEVICE_WITH_CREDS)

        monkeypatch.setattr(dvm_tools, "get_faz_client", lambda: FakeClient())

        result = await dvm_tools.get_device_info(device="FGT-01", adom="root")

        assert result["status"] == "success"
        assert result["device"]["adm_pass"] == MASK_VALUE


class TestIncidentInputValidation:
    """create_incident/update_incident must reject invalid severity/status."""

    async def test_create_incident_rejects_invalid_severity(self) -> None:
        result = await incident_tools.create_incident(name="Test", severity="catastrophic")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_update_incident_rejects_invalid_status(self) -> None:
        result = await incident_tools.update_incident(incident_id="INC-1", status="bogus")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_update_incident_rejects_invalid_severity(self) -> None:
        result = await incident_tools.update_incident(incident_id="INC-1", severity="bogus")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_create_incident_accepts_valid_severity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def create_incident(self, **kwargs: Any) -> dict[str, Any]:
                return {"id": "INC-9"}

        monkeypatch.setattr(incident_tools, "get_faz_client", lambda: FakeClient())

        result = await incident_tools.create_incident(name="Test", severity="High")
        assert result["status"] == "success"
        assert result["severity"] == "high"


class TestDvmMutationValidation:
    """add/delete device tools must validate adom and device names."""

    async def test_add_device_rejects_bad_adom(self) -> None:
        result = await dvm_tools.add_device(adom="root; rm -rf /", name="FGT-X", ip="10.0.0.1")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_delete_device_rejects_bad_name(self) -> None:
        result = await dvm_tools.delete_device(adom="root", device="x/../../etc")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]


class TestRunAndWaitReportVerifiesCompletion:
    """Regression: tid vanishing from the running list was reported as success
    without checking whether the report actually generated."""

    @staticmethod
    def _fake_client(fetch_result: dict[str, Any] | Exception) -> Any:
        class FakeClient:
            async def get_report_schedules(
                self, adom: str, layout_id: int | None = None
            ) -> dict[str, Any]:
                return {"data": [{"schedule": str(layout_id)}]}

            async def report_run(
                self,
                adom: str,
                layout_id: int,
                time_period: str = "last-7-days",
                device: list[dict[str, str]] | None = None,
            ) -> dict[str, Any]:
                return {"tid": "TID-1"}

            async def get_running_reports(self, adom: str) -> dict[str, Any]:
                return {"data": []}  # tid never appears -> vanish branch

            async def report_fetch(self, adom: str, tid: str) -> dict[str, Any]:
                if isinstance(fetch_result, Exception):
                    raise fetch_result
                return fetch_result

        return FakeClient()

    async def test_generated_state_is_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = self._fake_client({"state": "generated", "progress-percent": 100})
        monkeypatch.setattr(report_tools, "get_faz_client", lambda: client)

        result = await report_tools.run_and_wait_report(layout="4", adom="root")
        assert result["status"] == "success"
        assert result["tid"] == "TID-1"

    async def test_non_generated_state_is_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = self._fake_client({"state": "aborted", "progress-percent": 40})
        monkeypatch.setattr(report_tools, "get_faz_client", lambda: client)

        result = await report_tools.run_and_wait_report(layout="4", adom="root")
        assert result["status"] == "error"
        assert "aborted" in result["message"]

    async def test_unknown_tid_is_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = self._fake_client(RuntimeError("Cannot find a report uuid=TID-1"))
        monkeypatch.setattr(report_tools, "get_faz_client", lambda: client)

        result = await report_tools.run_and_wait_report(layout="4", adom="root")
        assert result["status"] == "error"

    async def test_startup_race_keeps_polling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Fetch says running while the tid is absent from the running list
        (startup race): keep polling rather than declaring failure."""
        states = iter([{"state": "running"}, {"state": "generated"}])

        class FakeClient:
            async def get_report_schedules(
                self, adom: str, layout_id: int | None = None
            ) -> dict[str, Any]:
                return {"data": [{"schedule": str(layout_id)}]}

            async def report_run(
                self,
                adom: str,
                layout_id: int,
                time_period: str = "last-7-days",
                device: list[dict[str, str]] | None = None,
            ) -> dict[str, Any]:
                return {"tid": "TID-1"}

            async def get_running_reports(self, adom: str) -> dict[str, Any]:
                return {"data": []}

            async def report_fetch(self, adom: str, tid: str) -> dict[str, Any]:
                return next(states)

        async def no_sleep(_seconds: float) -> None:
            return None

        monkeypatch.setattr(report_tools, "get_faz_client", lambda: FakeClient())
        monkeypatch.setattr(report_tools.asyncio, "sleep", no_sleep)

        result = await report_tools.run_and_wait_report(layout="4", adom="root")
        assert result["status"] == "success"
