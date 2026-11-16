"""Shared logic extracted from coverity_to_cid_data.py. Secrets come from env vars only.

All functions here are read-only against Coverity: search, issue lookup, discovery
(projects/streams/checkers/snapshots), audit history, and source-code info. Nothing
in this module writes to Coverity.
"""
import os, json, requests

DEFAULT_FILTERED_TYPES = [
    "Calling risky function", "'Constant' variable guards dead code",
    "Dereference after null check", "Dereference before null check",
    "Logically dead code", "Structurally dead code", "Unused value",
]

# Columns requested from issues/search. Keeping the keys stable means callers get a
# dict per issue instead of positional rows.
DEFAULT_COLUMNS = ["cid", "displayType", "status", "severity", "classification",
                   "owner", "firstDetected", "cwe", "function", "file"]

def cfg(name, default=None, required=False):
    v = os.environ.get(name, default)
    if required and not v:
        raise RuntimeError(f"Missing required environment variable {name}")
    return v

def coverity_session():
    s = requests.Session()
    s.auth = (cfg("COVERITY_USERNAME", required=True), cfg("COVERITY_AUTH_KEY", required=True))
    s.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
    return s

def host():
    return cfg("COVERITY_HOST", "scan4.scan.coverity.com")

# --- low-level helpers -------------------------------------------------------

def _request(method, path, params=None, payload=None):
    r = coverity_session().request(method, f"https://{host()}{path}", params=params,
                                   data=json.dumps(payload) if payload is not None else None)
    r.raise_for_status()
    if not r.content:
        return {}
    try:
        return r.json()
    except ValueError:
        return {"raw": r.text}

def _is_missing_endpoint(e):
    return e.response is not None and e.response.status_code in (404, 405)

def _unwrap(item):
    """Unwrap single-key wrappers such as {"project": {...}} or {"stream": {...}}."""
    if isinstance(item, dict) and len(item) == 1:
        (_, v), = item.items()
        if isinstance(v, dict):
            return v
    return item

def _extract_list(j):
    if isinstance(j, list):
        return [_unwrap(i) for i in j]
    if not isinstance(j, dict):
        return []
    for key in ("items", "rows", "data", "results"):
        v = j.get(key)
        if isinstance(v, list):
            return [_unwrap(i) for i in v]
    if len(j) == 1:
        v = next(iter(j.values()))
        if isinstance(v, list):
            return [_unwrap(i) for i in v]
    return []

def _items(j, *keys):
    if isinstance(j, dict):
        for key in keys:
            v = j.get(key)
            if isinstance(v, list):
                return [_unwrap(i) for i in v]
    return _extract_list(j)

def _cell(v):
    return v.get("value") if isinstance(v, dict) and "value" in v else v

def _rows_to_dicts(j, columns):
    labels = []
    for c in j.get("columns") or []:
        if isinstance(c, str):
            labels.append(c)
        elif isinstance(c, dict):
            labels.append(c.get("key") or c.get("value") or c.get("label"))
    if len(labels) != len(columns):
        labels = list(columns)
    return [{lab: _cell(v) for lab, v in zip(labels, row)} for row in j.get("rows") or []]

# --- discovery / read-only endpoints ----------------------------------------

def get_current_user():
    """Authenticated account. Useful as a connectivity/credential check."""
    return _request("GET", "/api/v2/users/current")

def list_projects():
    return _items(_request("GET", "/api/v2/projects"), "projects")

def list_streams():
    return _items(_request("GET", "/api/v2/streams"), "streams")

def list_checkers():
    """Checker metadata (CWE, subcategory, description) for enriching defect summaries."""
    return _items(_request("GET", "/api/v2/checkers"), "checkers")

def list_stream_snapshots(stream_id):
    """Snapshot history for a stream: gives 'open' a concrete scan to hang off."""
    try:
        j = _request("GET", f"/api/v2/streams/{stream_id}/snapshots")
    except requests.HTTPError as e:
        if not _is_missing_endpoint(e):
            raise
        j = _request("GET", "/api/v2/snapshots", params={"streamId": stream_id})
    return _items(j, "snapshots")

def search_issues(project_name, columns=None, statuses=None, severities=None,
                  checkers=None, limit=None, offset=0, sort_order="asc"):
    """POST issues/search with server-side filters; returns one dict per issue.

    limit=None means rowCount=-1 (all rows). Filters are applied by Coverity, not
    client-side, so paging and large projects stay cheap.
    """
    cols = list(columns or DEFAULT_COLUMNS)
    filters = [{"columnKey": "project", "matchMode": "oneOrMoreMatch",
                "matchers": [{"class": "Project", "name": project_name, "type": "nameMatcher"}]}]
    if statuses:
        filters.append({"columnKey": "status", "matchMode": "oneOrMoreMatch",
                        "matchers": [{"class": "Status", "name": s} for s in statuses]})
    if severities:
        filters.append({"columnKey": "severity", "matchMode": "oneOrMoreMatch",
                        "matchers": [{"class": "Severity", "name": s} for s in severities]})
    if checkers:
        filters.append({"columnKey": "checker", "matchMode": "oneOrMoreMatch",
                        "matchers": [{"class": "Checker", "name": s} for s in checkers]})
    params = {"includeColumnLabels": "true", "locale": "en_us", "queryType": "bySnapshot",
              "offset": offset, "rowCount": -1 if limit is None else limit,
              "sortOrder": sort_order}
    j = _request("POST", "/api/v2/issues/search", params=params,
                 payload={"filters": filters, "columns": cols})
    return _rows_to_dicts(j, cols)

def get_issue(cid):
    """Full issue record: status, classification, severity, owner, firstDetected, cwe."""
    return _request("GET", f"/api/v2/issues/{cid}")

def get_issue_audit(cid):
    """Triage history for a CID (status/owner changes, comments)."""
    try:
        return _request("GET", f"/api/v2/issues/{cid}/audit")
    except requests.HTTPError as e:
        if not _is_missing_endpoint(e):
            raise
    return _request("GET", "/api/v2/issues/audit", params={"cid": cid})

def get_all_cids(project_name, filtered_types=None):
    """Return CIDs for a project. Dismissed issues are always excluded.
    filtered_types lists checker display types to skip (defaults to
    DEFAULT_FILTERED_TYPES); pass an empty list to keep every non-dismissed issue."""
    if filtered_types is None:
        filtered_types = DEFAULT_FILTERED_TYPES
    skip_types = set(filtered_types)
    rows = search_issues(project_name, columns=["cid", "displayType", "status"])
    out = []
    for row in rows:
        if row.get("status") == "Dismissed":
            continue
        if row.get("displayType") in skip_types:
            continue
        out.append(int(row["cid"]))
    return out

def get_source_code_info(cid, stream_name):
    r = coverity_session().get(f"https://{host()}/api/v2/issues/sourceCodeInfo",
        params={"cid": cid, "streamName": stream_name, "includeTotalIssueOccurrencesCount": "true"})
    r.raise_for_status()
    return r.json()

def get_source_code_info_batch(cids, stream_name):
    """Batch sourceCodeInfo for many CIDs. Returns {cid: raw}. Raises ValueError when the
    response is not per-CID source info, so callers can fall back to single fetches."""
    cids = [int(c) for c in cids]
    j = _request("POST", "/api/v2/issues/sourceCodeInfo/search",
                 payload={"streamName": stream_name, "cids": cids})
    items = _extract_list(j)
    out = {}
    for i, item in enumerate(items):
        item = _unwrap(item)
        if not isinstance(item, dict) or "issueOccurrences" not in item:
            continue
        cid = item.get("cid", cids[i] if i < len(cids) else None)
        if cid is not None:
            out[int(cid)] = item
    if not out:
        raise ValueError("unrecognized sourceCodeInfo/search response")
    return out

# --- shaping ----------------------------------------------------------------

def summarize_source_info(info, max_occurrences=1):
    occs = info.get("issueOccurrences", [])
    samples = []
    for occ in occs[:max_occurrences]:
        ev = [{"line": e.get("lineNumber"), "filePathname": e.get("file", {}).get("filePathname"),
               "description": e.get("eventDescription"), "tag": e.get("eventTag"),
               "isMainEvent": bool(e.get("main"))}
              for e in occ.get("events", []) if e.get("eventKind") == "PATH" or e.get("main")]
        samples.append({"occurrenceId": occ.get("id"), "localEffect": occ.get("localEffect"), "events": ev})
    return {"checkerName": info.get("checkerName"), "subcategory": info.get("subcategory"),
            "cwe": info.get("cwe"), "functionName": info.get("functionName"),
            "filePathname": info.get("filePathname"),
            "longDescription": occs[0].get("longDescription") if occs else None,
            "totalOccurrences": len(occs), "sampleOccurrences": samples}

def consolidate_defect(d):
    latest = max(d["issueOccurrences"], key=lambda o: int(o["id"]))
    main = next((e for e in latest["events"] if e.get("main")), latest["events"][-1])
    return {"checkerName": d["checkerName"], "domain": d["domain"],
            "totalOccurrences": d["issueOccurrencesCount"], "latestOccurrenceId": latest["id"],
            "file": main["file"]["filePathname"], "fileMD5": main["file"]["contentsMD5"],
            "mainLine": main["lineNumber"], "localEffect": latest["localEffect"],
            "longDescription": latest["longDescription"],
            "events": [{"eventNumber": e["eventNumber"], "eventTag": e["eventTag"],
                        "lineNumber": e["lineNumber"], "description": e["eventDescription"],
                        "isMain": bool(e.get("main"))} for e in latest["events"]]}

def save_json(data, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
