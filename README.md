# Coverity MCP servers for OpenCode

Read-only access to Coverity Connect via the Model Context Protocol. Nothing here
writes to Coverity.

## Server

| Server | Tools |
|---|---|
| `coverity` | `check_connection`, `list_projects`, `list_streams`, `list_checkers`, `list_stream_snapshots`, `list_issues`, `list_defect_cids`, `get_issue`, `get_issue_audit`, `get_defect_source_info`, `get_defect_summary`, `export_all_cid_data` |

Filtering: Dismissed defects are always excluded. `filtered_types` is the list of checker
display types to skip (omit for the built-in low-value set; pass an empty list to keep
every non-dismissed defect).

`list_issues` returns a single page by default (limit 100, offset 0). Set `paginate=true`
to fetch every matching issue across all pages; `limit` then controls the page size.

## Integrate with OpenCode (3 steps)

### 1. Install uv and sync dependencies

The MCP servers are launched via `uv run`, which manages the Python environment
and installs `mcp` and `requests` from `pyproject.toml`/`uv.lock` automatically:

```bash
cd /path/to/coverity_mcp
uv sync
```

### 2. Configure credentials

Copy the env template and fill in your Coverity auth key:

```bash
cp .env.example .env
# edit .env with your COVERITY_USERNAME and COVERITY_AUTH_KEY
```

Then export them into your shell (or your shell's rc file):

```bash
set -a; . .env; set +a
```

### 3. Generate and merge the OpenCode MCP config

Do **not** use `opencode.json.example` directly — it contains
`/ABSOLUTE/PATH/TO/coverity_mcp` placeholders that must be replaced with real paths.

Instead, run the setup script, which computes your absolute path and emits a valid
config block:

```bash
./setup.sh > coverity-mcp.opencode.json
```

Then merge the `"mcp"` block into your OpenCode config:

- **Global:** `~/.config/opencode/opencode.json`
- **Project-level:** `./opencode.json`

`setup.sh` output looks like:

```json
{
  "mcp": {
    "coverity": {
      "type": "local",
      "command": ["uv", "run", "--directory", "/home/user/coverity_mcp", "python3", "/home/user/coverity_mcp/coverity_server.py"],
      "enabled": true,
      "environment": {
        "COVERITY_USERNAME": "{env:COVERITY_USERNAME}",
        "COVERITY_AUTH_KEY": "{env:COVERITY_AUTH_KEY}",
        "PYTHONPATH": "/home/user/coverity_mcp"
      }
    }
  }
}
```

`opencode.json.example` is kept as a static reference if you prefer to edit by hand,
but you must replace every `/ABSOLUTE/PATH/TO/coverity_mcp` with your real path.

Easy approach to install into opencode:
```
jq -s '.[0] * .[1]' ~/.config/opencode/opencode.json coverity-mcp.opencode.json > /tmp/m.json && mv /tmp/m.json ~/.config/opencode/opencode.json
```

### 4. Restart OpenCode and verify

Restart OpenCode, then run:

```
check_connection
```

It should return `{"authenticated": true, ...}`. If it returns `false`, check your
`COVERITY_USERNAME` / `COVERITY_AUTH_KEY` and `COVERITY_HOST`.

## Test

```bash
uv run pytest test_coverity.py test_coverity_live.py -v
```

The live tests skip automatically when `COVERITY_USERNAME` / `COVERITY_AUTH_KEY` are
not set.

## Notes

- All endpoints are read-only. No GitHub ticket filing, no Coverity triage writes.
- `COVERITY_HOST` defaults to `scan4.scan.coverity.com`. Override with the env var if
  your instance is elsewhere.

