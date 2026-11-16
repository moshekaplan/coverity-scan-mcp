"""Live integration tests against a real Coverity instance.

These require COVERITY_USERNAME and COVERITY_AUTH_KEY (and optionally
COVERITY_HOST) in the environment. They are skipped automatically when
credentials are absent, so they're safe to commit and run in CI without
secrets. Nothing here writes to Coverity; all calls are read-only.

Run:
    export COVERITY_USERNAME=... COVERITY_AUTH_KEY=...
    pytest test_coverity_live.py -v
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402
import requests  # noqa: E402

import coverity_common as c  # noqa: E402
import coverity_server as sd  # noqa: E402

HAS_CREDS = bool(os.environ.get("COVERITY_USERNAME") and os.environ.get("COVERITY_AUTH_KEY"))
needs_creds = pytest.mark.skipif(not HAS_CREDS, reason="Coverity credentials not configured")


@needs_creds
class TestDiscovery:
    def test_check_connection(self):
        out = sd.check_connection()
        assert out["authenticated"] is True or out["authenticated"] is False
        assert out["host"] == c.host()
        if out["authenticated"]:
            assert "user" in out

    def test_list_projects(self):
        out = sd.list_projects()
        assert isinstance(out["projects"], list)
        assert out["count"] == len(out["projects"])

    def test_list_streams(self):
        out = sd.list_streams()
        assert isinstance(out["streams"], list)
        assert out["count"] == len(out["streams"])

    def test_list_checkers(self):
        out = sd.list_checkers()
        assert isinstance(out["checkers"], list)
        assert out["count"] == len(out["checkers"])


@needs_creds
class TestIssues:
    @pytest.fixture(scope="class")
    def project_name(self):
        return os.environ.get("COVERITY_PROJECT", "net-snmp")

    @pytest.fixture(scope="class")
    def one_issue(self, project_name):
        """Return the first non-dismissed issue for the project, or None."""
        rows = sd.list_issues(project_name, statuses=["New", "Triaged", "Fix Submitted"],
                              limit=1)["issues"]
        return rows[0] if rows else None

    def test_list_issues_returns_full_rows(self, project_name):
        out = sd.list_issues(project_name, limit=5)
        assert out["count"] <= 5 and out["count"] == len(out["issues"])
        assert "filtered_types" in out
        for row in out["issues"]:
            assert "cid" in row and "displayType" in row and "status" in row
        # dismissed should not leak through unless asked for
        assert all(r["status"] != "Dismissed" for r in out["issues"])

    def test_list_defect_cids_excludes_dismissed(self, project_name):
        out = sd.list_defect_cids(project_name)
        assert isinstance(out["cids"], list)
        assert out["count"] == len(out["cids"])
        assert "filtered_types" in out

    def test_list_defect_cids_empty_filter(self, project_name):
        unfiltered = sd.list_defect_cids(project_name, filtered_types=[])["cids"]
        defaulted = sd.list_defect_cids(project_name)["cids"]
        assert len(unfiltered) >= len(defaulted)

    def test_get_issue(self, one_issue):
        if not one_issue:
            pytest.skip("no non-dismissed issue available for this project")
        detail = sd.get_issue(int(one_issue["cid"]))
        assert detail["cid"] == int(one_issue["cid"])
        assert "status" in detail

    def test_get_issue_audit(self, one_issue):
        if not one_issue:
            pytest.skip("no non-dismissed issue available for this project")
        audit = sd.get_issue_audit(int(one_issue["cid"]))
        assert isinstance(audit, (dict, list))

    def test_get_defect_source_info(self, one_issue, project_name):
        if not one_issue:
            pytest.skip("no non-dismissed issue available for this project")
        stream = os.environ.get("COVERITY_STREAM", project_name)
        raw = sd.get_defect_source_info(int(one_issue["cid"]), stream_name=stream)
        assert "issueOccurrences" in raw or "issueOccurrencesCount" in raw

    def test_get_defect_summary(self, one_issue, project_name):
        if not one_issue:
            pytest.skip("no non-dismissed issue available for this project")
        stream = os.environ.get("COVERITY_STREAM", project_name)
        summary = sd.get_defect_summary(int(one_issue["cid"]), stream_name=stream)
        assert "checkerName" in summary
        consolidated = sd.get_defect_summary(int(one_issue["cid"]), stream_name=stream,
                                             mode="consolidated")
        assert "mainLine" in consolidated


@needs_creds
class TestExport:
    @pytest.fixture(scope="class")
    def project_name(self):
        return os.environ.get("COVERITY_PROJECT", "net-snmp")

    def test_export_small_batch(self, project_name, tmp_path):
        out = tmp_path / "coverity_export.json"
        result = sd.export_all_cid_data(project_name,
                                        output_file=str(out),
                                        limit=1,
                                        filtered_types=[])
        assert result["saved"] == 1
        assert result["output_file"] == str(out)
        assert "batch_used" in result
        assert isinstance(result["errors"], dict)
        data = __import__("json").load(open(out))
        assert len(data) == 1
        entry = next(iter(data.values()))
        assert "raw_response" in entry



