# MCP Shield

**Security scanner for Model Context Protocol (MCP) server configurations.**

![PyPI version](https://img.shields.io/pypi/v/mcpshield)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![CI](https://img.shields.io/github/actions/workflow/status/Arkya-AI/mcpshield/ci.yml)

---

> **38.7% of MCP servers have zero authentication. Is yours secure?**

MCP Shield audits your MCP server configuration for credential exposure, insecure transports, over-permissioned servers, and known CVEs — in seconds, before you ship.

---

## Install

```bash
pip install mcpshield
```

Requires Python 3.11+.

---

## Quick Start

Point it at your Claude Desktop (or any MCP-compatible) config file:

```bash
mcpshield scan ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

Sample output:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━ MCP Shield Security Scan ━━━━━━━━━━━━━━━━━━━━━━━━━

┌─────────────────────────┐
│      Security Grade      │
│                          │
│            F             │
│       Score: 22/100      │
│   Server: filesystem     │
└─────────────────────────┘

─────────────────────── CRITICAL (1) ────────────────────────
┌──────────────────┬────────────────────────────────┬─────────────────────────────────────────┐
│ Check ID         │ Title                          │ Remediation                             │
├──────────────────┼────────────────────────────────┼─────────────────────────────────────────┤
│ CVE001           │ CVE-2025-6514 (CVSS 9.6) —     │ Upgrade mcp-remote to 0.1.18 or later.  │
│                  │ vulnerable package detected     │                                         │
└──────────────────┴────────────────────────────────┴─────────────────────────────────────────┘

──────────────────────── HIGH (2) ───────────────────────────
┌──────────────────┬────────────────────────────────┬─────────────────────────────────────────┐
│ Check ID         │ Title                          │ Remediation                             │
├──────────────────┼────────────────────────────────┼─────────────────────────────────────────┤
│ AUTH001          │ Server uses plaintext HTTP     │ Switch to HTTPS with a valid TLS cert.  │
│ CRED001          │ Hardcoded secret in env var    │ Move to a secrets manager or .env file. │
│                  │ 'API_KEY'                       │                                         │
└──────────────────┴────────────────────────────────┴─────────────────────────────────────────┘

─────────────────────────── Summary ─────────────────────────
  Server        Grade   Score   Critical   High   Medium   Low
  filesystem    F       22      1          2      1        0

╭─ Recommendation ────────────────────────────────────────────────────────╮
│ Action required: Critical security issues detected.                      │
│ Do not deploy to production until resolved.                              │
╰─────────────────────────────────────────────────────────────────────────╯
```

Grades range from **A** (secure) to **F** (critical issues — do not deploy).

---

## What It Checks

| Check ID   | Name                    | What It Catches                                                                              |
|------------|-------------------------|----------------------------------------------------------------------------------------------|
| `AUTH001`  | Authentication          | Missing auth tokens, plaintext HTTP transports, servers bound to 0.0.0.0 or public IPs      |
| `CRED001`  | Credential Exposure     | Hardcoded secrets in env vars, tokens passed as CLI args, sensitive filesystem paths         |
| `TRANS001` | Transport Security      | Privilege escalation (`sudo`), shell interpreter commands, deprecated SSE transport          |
| `PERM001`  | Over-Permission         | Admin/root-level env vars, wildcard scopes, god-mode flags                                   |
| `HYGN001`  | Config Hygiene          | Placeholder values, duplicate server names, missing commands/URLs, excessive server counts   |
| `CVE001`   | Known CVEs              | Packages affected by CVE-2025-6514 (CVSS 9.6), CVE-2025-49596, CVE-2025-53364 and more     |

---

## Web Scanner

Don't want to install anything? Try it online:

**[mcpshield-api-production.up.railway.app](https://mcpshield-api-production.up.railway.app)**

Paste your config or drop in a URL. Results in under a second. Nothing is stored.

---

## REST API

MCP Shield exposes a JSON API for CI pipelines and integrations.

**Scan a config file:**

```bash
curl -X POST https://mcpshield-api-production.up.railway.app/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "mcpServers": {
        "my-server": {
          "command": "npx",
          "args": ["-y", "mcp-remote", "https://api.example.com/mcp"],
          "env": {}
        }
      }
    }
  }'
```

**Scan a remote URL:**

```bash
curl -X POST https://mcpshield-api-production.up.railway.app/api/v1/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://my-mcp-server.internal:8080"}'
```

**Response shape:**

```json
{
  "metadata": {
    "scan_timestamp": "2025-06-15T12:00:00Z",
    "mcpshield_version": "0.1.0",
    "total_findings": 3,
    "severity_totals": {"critical": 1, "high": 2},
    "server_count": 1,
    "duration_ms": 12.4
  },
  "results": [
    {
      "server_name": "my-server",
      "grade": "F",
      "score": 22,
      "findings": [...]
    }
  ]
}
```

Interactive API docs: [mcpshield-api-production.up.railway.app/docs](https://mcpshield-api-production.up.railway.app/docs)

---

## Output Formats

```bash
# Default: rich terminal output
mcpshield scan config.json

# Machine-readable JSON
mcpshield scan config.json --format json

# Save to file
mcpshield scan config.json --format json --output report.json

# Filter by severity
mcpshield scan config.json --severity-threshold high

# Scan a remote URL directly
mcpshield scan-url https://my-mcp-server.example.com
```

Exit codes: `0` = clean, `2` = critical findings detected. CI-friendly by design.

---

## CI Integration

```yaml
# GitHub Actions example
- name: Scan MCP config
  run: |
    pip install mcpshield
    mcpshield scan mcp_config.json --severity-threshold high --format json --output mcp-report.json
  # Exit code 2 = critical findings → fails the build
```

---

## Supported Config Formats

- **Claude Desktop** (`mcpServers` key) — drop in your `claude_desktop_config.json` directly
- **Generic MCP** (`servers` key) — any config following the MCP spec

---

## Contributing

Bug reports and pull requests are welcome.

```bash
git clone https://github.com/Arkya-AI/mcpshield
cd mcpshield
pip install -e ".[dev]"
pytest
```

To add a new check, subclass `BaseCheck` in `src/mcpshield/checks/` and register it in `src/mcpshield/checks/__init__.py`. See existing checks for the pattern.

---

## License

MIT — see [LICENSE](LICENSE).

---

Built by [TimoLabs](https://timolabs.dev)
