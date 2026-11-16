#!/usr/bin/env bash
# setup.sh — generate an OpenCode MCP config with real absolute paths,
# ready to merge into your opencode config.
#
# Usage:
#   cd /path/to/coverity_mcp
#   ./setup.sh > coverity-mcp.opencode.json
#   # then merge the "mcp" block into your opencode config:
#   #   ~/.config/opencode/opencode.json   (global)
#   #   or ./opencode.json                 (project-level)
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cat <<EOF
{
  "mcp": {
    "coverity": {
      "type": "local",
      "command": [
        "uv",
        "run",
        "--directory",
        "${DIR}",
        "python3",
        "${DIR}/coverity_server.py"
      ],
      "enabled": true,
      "environment": {
        "COVERITY_USERNAME": "{env:COVERITY_USERNAME}",
        "COVERITY_AUTH_KEY": "{env:COVERITY_AUTH_KEY}",
        "PYTHONPATH": "${DIR}"
      }
    }
  }
}
EOF
