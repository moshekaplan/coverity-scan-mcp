"""MCP server: Coverity read-only tools (defects + export).

Single MCP server exposing all Coverity Connect read-only endpoints:
discovery (projects/streams/checkers/snapshots), issue search/lookup,
defect source info, and bulk CID export.
"""
from typing import Literal
from mcp.server.mcpserver import MCPServer
import requests
import coverity_common as c

mcp = MCPServer("coverity")

# --- export constants -------------------------------------------------------

BATCH_SIZE = 50
SAVE_EVERY = 25

# --- connection / discovery -------------------------------------------------

@mcp.tool()
def check_connection() -> dict:
    """Verify the Coverity host and credentials. Read-only; returns the authenticated user."""
    try:
        user = c.get_current_user()
    except requests.HTTPError as e:
        return {"authenticated": False, "host": c.host(),
                "status": e.response.status_code if e.response is not None else None,
                "error": str(e)}
    return {"authenticated": True, "host": c.host(), "user": user}

@mcp.tool()
def list_projects() -> dict:
    """List Coverity projects visible to the authenticated user."""
    items = c.list_projects()
    return {"count": len(items), "projects": items}

@mcp.tool()
def list_streams() -> dict:
    """List Coverity streams. Use these names for stream_name arguments."""
    items = c.list_streams()
    return {"count": len(items), "streams": items}

@mcp.tool()
def list_checkers() -> dict:
    """List checker metadata (CWE, subcategory, description) used for filtered_types."""
    items = c.list_checkers()
    return {"count": len(items), "checkers": items}

@mcp.tool()
def list_stream_snapshots(stream_id: str) -> dict:
    """List snapshots for a stream, so a defect list can be tied to a concrete scan."""
    items = c.list_stream_snapshots(stream_id)
    return {"stream": stream_id, "count": len(items), "snapshots": items}

# --- issue search / lookup --------------------------------------------------

@mcp.tool()
def list_issues(project_name: str = "net-snmp",
                statuses: list[str] | None = None,
                severities: list[str] | None = None,
                checkers: list[str] | None = None,
                filtered_types: list[str] | None = None,
                limit: int = 100, offset: int = 0,
                sort_order: Literal["asc", "desc"] = "asc",
                paginate: bool = False) -> dict:
    """Search open issues and return full rows (cid, displayType, status, severity,
    classification, owner, firstDetected, cwe, function, file) filtered by Coverity itself.
    Dismissed defects are always excluded unless statuses explicitly includes "Dismissed".
    filtered_types overrides the checker display types to skip (omit for the built-in
    low-value set, empty list for none).
    Set paginate=True to fetch every matching issue across all pages; limit then
    controls the page size (default 100)."""
    types = c.DEFAULT_FILTERED_TYPES if filtered_types is None else filtered_types
    skip_types = set(types)
    include_dismissed = bool(statuses) and "Dismissed" in statuses

    def _filter(rows):
        return [r for r in rows
                if (include_dismissed or r.get("status") != "Dismissed")
                and r.get("displayType") not in skip_types]

    if paginate:
        all_issues = []
        page_offset = max(offset, 0)
        page_size = max(limit, 1)
        while True:
            rows = c.search_issues(project_name, statuses=statuses, severities=severities,
                                   checkers=checkers, limit=page_size, offset=page_offset,
                                   sort_order=sort_order)
            if not rows:
                break
            all_issues.extend(rows)
            if len(rows) < page_size:
                break
            page_offset += page_size
        issues = _filter(all_issues)
        return {"project": project_name, "count": len(issues), "offset": offset,
                "filtered_types": list(types), "paginated": True, "issues": issues}

    rows = c.search_issues(project_name, statuses=statuses, severities=severities,
                           checkers=checkers, limit=limit, offset=offset,
                           sort_order=sort_order)
    issues = _filter(rows)
    return {"project": project_name, "count": len(issues), "offset": offset,
            "filtered_types": list(types), "issues": issues}

@mcp.tool()
def list_defect_cids(project_name: str = "net-snmp",
                     filtered_types: list[str] | None = None) -> dict:
    """List open Coverity CIDs for a project. Dismissed defects are always excluded.
    filtered_types is the list of checker display types to skip; omit it to use the
    built-in low-value set (dead code, null-check ordering, unused value, risky function),
    or pass an empty list to keep every non-dismissed defect. Use list_issues when you
    need severity/owner/file rather than bare CIDs."""
    types = c.DEFAULT_FILTERED_TYPES if filtered_types is None else filtered_types
    cids = c.get_all_cids(project_name, types)
    return {"project": project_name, "count": len(cids),
            "filtered_types": list(types), "cids": cids}

@mcp.tool()
def get_issue(cid: int) -> dict:
    """Full issue record: triage status, classification, severity, owner, firstDetected,
    cwe, checker, component, function, file."""
    return c.get_issue(cid)

@mcp.tool()
def get_issue_audit(cid: int) -> dict:
    """Triage history for a CID: who changed status/owner and any comments."""
    return c.get_issue_audit(cid)

@mcp.tool()
def get_defect_source_info(cid: int, stream_name: str = "net-snmp") -> dict:
    """Raw Coverity sourceCodeInfo JSON for a CID (can be large)."""
    return c.get_source_code_info(cid, stream_name)

@mcp.tool()
def get_defect_summary(cid: int, stream_name: str = "net-snmp",
                       mode: Literal["brief", "consolidated"] = "consolidated",
                       max_occurrences: int = 1) -> dict:
    """Compact defect view for debugging/patching. 'consolidated' uses the latest occurrence
    with the full event trace; 'brief' returns checker/CWE/function plus sample occurrences."""
    info = c.get_source_code_info(cid, stream_name)
    if mode == "consolidated":
        return c.consolidate_defect(info)
    return c.summarize_source_info(info, max_occurrences)

# --- bulk export ------------------------------------------------------------

@mcp.tool()
def export_all_cid_data(project_name: str = "net-snmp", stream_name: str = "net-snmp",
                        output_file: str = "coverity_cid_data.json", limit: int | None = None,
                        filtered_types: list[str] | None = None) -> dict:
    """Fetch every open CID and save raw + summarized data to a local JSON file.
    Dismissed defects are always excluded; filtered_types overrides the checker types to
    skip (omit for the built-in low-value set, empty list for all non-dismissed).
    Uses the batch sourceCodeInfo endpoint when available, falling back to one request
    per CID. Use 'limit' to cap the number of CIDs. Saves incrementally."""
    cids = c.get_all_cids(project_name, filtered_types)
    if limit:
        cids = cids[:limit]
    data, errors = {}, {}
    batch_ok = True
    since_save = 0

    def record(cid, raw):
        nonlocal since_save
        try:
            data[cid] = {"raw_response": raw, "summarized": c.consolidate_defect(raw)}
        except (KeyError, ValueError) as e:
            data[cid] = {"error": str(e)}
            errors[cid] = str(e)
        since_save += 1
        if since_save >= SAVE_EVERY:
            c.save_json(data, output_file)
            since_save = 0

    pending = list(cids)
    while pending:
        batch, pending = pending[:BATCH_SIZE], pending[BATCH_SIZE:]

        if batch_ok:
            try:
                infos = c.get_source_code_info_batch(batch, stream_name)
            except (requests.HTTPError, ValueError):
                batch_ok = False
            else:
                for cid in batch:
                    raw = infos.get(cid)
                    if raw is None:
                        errors[cid] = "missing from batch response"
                        data[cid] = {"error": errors[cid]}
                    else:
                        record(cid, raw)
                c.save_json(data, output_file)
                since_save = 0
                continue

        for cid in batch:
            try:
                record(cid, c.get_source_code_info(cid, stream_name))
            except (requests.HTTPError, KeyError, ValueError) as e:
                data[cid] = {"error": str(e)}
                errors[cid] = str(e)
                since_save += 1

    c.save_json(data, output_file)
    return {"saved": len(data), "errors": errors, "output_file": output_file,
            "batch_used": batch_ok}

if __name__ == "__main__":
    mcp.run()
