"""Fast, network-free unit tests for coverity_common shaping logic.

These never touch Coverity; they verify row parsing, dismissal filtering,
checker filtering, and batch-response handling in isolation.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import coverity_common as c  # noqa: E402


def test_rows_to_dicts_uses_returned_labels():
    j = {
        "columns": [{"key": "cid"}, {"key": "displayType"}, {"key": "status"}],
        "rows": [
            [{"value": 1}, {"value": "Buffer overflow"}, {"value": "New"}],
            [{"value": 2}, {"value": "Logically dead code"}, {"value": "Dismissed"}],
        ],
    }
    out = c._rows_to_dicts(j, ["cid", "displayType", "status"])
    assert out == [
        {"cid": 1, "displayType": "Buffer overflow", "status": "New"},
        {"cid": 2, "displayType": "Logically dead code", "status": "Dismissed"},
    ]


def test_get_all_cids_always_excludes_dismissed():
    def fake_search(project_name, columns=None, statuses=None, severities=None,
                    checkers=None, limit=None, offset=0, sort_order="asc"):
        return [
            {"cid": 1, "displayType": "Buffer overflow", "status": "New"},
            {"cid": 2, "displayType": "Buffer overflow", "status": "Dismissed"},
            {"cid": 3, "displayType": "Logically dead code", "status": "Triaged"},
        ]
    c.search_issues = fake_search

    # default filters drop both dismissed and dead-code checkers
    assert c.get_all_cids("p") == [1]

    # empty filter list keeps everything except dismissed
    assert c.get_all_cids("p", filtered_types=[]) == [1, 3]


def test_list_issues_paginate(monkeypatch):
    calls = []
    page_size = 2

    def fake_search(project_name, columns=None, statuses=None, severities=None,
                    checkers=None, limit=None, offset=0, sort_order="asc"):
        calls.append((limit, offset))
        # Simulate 5 total items, 2 per page
        all_items = [
            {"cid": 1, "displayType": "Buffer overflow", "status": "New"},
            {"cid": 2, "displayType": "Buffer overflow", "status": "Triaged"},
            {"cid": 3, "displayType": "Logically dead code", "status": "New"},
            {"cid": 4, "displayType": "Buffer overflow", "status": "Triaged"},
            {"cid": 5, "displayType": "Buffer overflow", "status": "New"},
        ]
        return all_items[offset:offset + page_size]

    import coverity_server as sd
    monkeypatch.setattr(c, "search_issues", fake_search)
    monkeypatch.setattr(sd, "c", c)

    out = sd.list_issues("p", paginate=True, limit=page_size, filtered_types=[])
    assert out["paginated"] is True
    assert out["count"] == 5
    assert [i["cid"] for i in out["issues"]] == [1, 2, 3, 4, 5]
    # Should have made 3 calls: offset 0, 2, 4; the last returns 1 item < page_size
    assert calls == [(page_size, 0), (page_size, 2), (page_size, 4)], calls


def test_list_issues_single_page_unchanged(monkeypatch):
    calls = []

    def fake_search(project_name, columns=None, statuses=None, severities=None,
                    checkers=None, limit=None, offset=0, sort_order="asc"):
        calls.append((limit, offset))
        return [{"cid": 1, "displayType": "Buffer overflow", "status": "New"}]

    import coverity_server as sd
    monkeypatch.setattr(c, "search_issues", fake_search)
    monkeypatch.setattr(sd, "c", c)

    out = sd.list_issues("p", paginate=False, limit=10, offset=0)
    assert out.get("paginated") is not True
    assert out["count"] == 1
    assert calls == [(10, 0)], calls


def test_batch_response_missing_shape_raises(monkeypatch):
    monkeypatch.setattr(c, "_request", lambda *a, **k: {"nonsense": [{"cid": 1}]})
    try:
        c.get_source_code_info_batch([1], "s")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_summarize_and_consolidate_shape():
    info = {
        "checkerName": "Buffer overflow", "domain": "memory", "cwe": "CWE-122", "subcategory": "memory",
        "functionName": "main", "filePathname": "src/a.c",
        "issueOccurrencesCount": 2,
        "issueOccurrences": [
            {"id": 5, "longDescription": "desc", "localEffect": "LE",
             "events": [{"eventNumber": 1, "eventTag": "CALL", "lineNumber": 3,
                         "eventDescription": "x", "main": True,
                         "file": {"filePathname": "src/a.c", "contentsMD5": "md5"}}]},
            {"id": 6, "longDescription": "desc2", "localEffect": "LE2",
             "events": [{"eventNumber": 1, "eventTag": "CALL", "lineNumber": 4,
                         "eventDescription": "y", "main": False,
                         "file": {"filePathname": "src/a.c", "contentsMD5": "md5"}}]},
        ],
    }
    brief = c.summarize_source_info(info)
    assert brief["checkerName"] == "Buffer overflow"
    assert brief["cwe"] == "CWE-122"
    assert brief["totalOccurrences"] == 2
    assert len(brief["sampleOccurrences"]) == 1

    full = c.consolidate_defect(info)
    assert full["checkerName"] == "Buffer overflow"
    assert full["totalOccurrences"] == 2
    assert full["latestOccurrenceId"] == 6
    assert full["mainLine"] == 4
    assert len(full["events"]) == 1


def test_env_required_missing(monkeypatch):
    monkeypatch.delenv("COVERITY_USERNAME", raising=False)
    monkeypatch.delenv("COVERITY_AUTH_KEY", raising=False)
    try:
        c.coverity_session()
        raise AssertionError("expected RuntimeError")
    except RuntimeError as e:
        assert "COVERITY_USERNAME" in str(e)
