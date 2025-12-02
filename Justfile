set dotenv-load
set export
set shell := ["bash", "-c"]

# Register the stdio MCP server with Codex CLI
register-codex-stdio:
    #!/usr/bin/env bash
    set -euo pipefail
    codex mcp add pm2-mcp -- pm2-mcp
    codex mcp list | grep -F "pm2-mcp" || true

# Start the MCP server over HTTP/Streamable transport (adjust host/port/path as needed)
run-mcp-http host="127.0.0.1" port="8849" path="/mcp":
    #!/usr/bin/env bash
    set -euo pipefail
    pm2-mcp --transport http --host {{host}} --port {{port}} --path {{path}}

# Register the HTTP transport endpoint with Codex CLI (server must already be running)
register-codex-http name="pm2-mcp-http" host="127.0.0.1" port="8849" path="/mcp":
    #!/usr/bin/env bash
    set -euo pipefail
    url="http://{{host}}:{{port}}{{path}}"
    codex mcp add {{name}} --url "$url"
    codex mcp list | grep -F "{{name}}" || true
