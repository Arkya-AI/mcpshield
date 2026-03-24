# State of MCP Security — March 2026

**Published by TimoLabs / MCP Shield | March 2026**

---

## Executive Summary

The Model Context Protocol has become the connective tissue of the agentic AI era. In under eighteen months, the ecosystem has grown to over 10,000 published MCP servers, with the official SDK pulling 97 million monthly downloads. Enterprise AI teams are racing to adopt it. Operating systems are building it into their core. The Linux Foundation just gave it a permanent home.

And nearly 2,000 of those servers are running in production with zero authentication.

This report documents the security state of the MCP ecosystem as of March 2026. The findings are not theoretical. Three CVEs with scores ranging from 7.5 to 9.6 have already been published against core MCP packages. Supply chain attacks are active. Rug-pull attacks — where tool definitions silently mutate after installation — are possible and largely undetected. Over-permissioned servers are the norm, not the exception.

The central finding: **38.7% of publicly available MCP servers require no authentication whatsoever.** In a protocol designed to give AI agents access to filesystems, databases, APIs, and code execution environments, this is not a misconfiguration footnote. It is a systemic vulnerability at the foundation of enterprise AI infrastructure.

---

## Methodology

This analysis draws on three data sources:

1. **Public server registry scan.** We analyzed publicly available MCP server configurations published to registries, GitHub repositories, and package registries (npm, PyPI). Server manifests, tool schemas, and authentication metadata were collected and evaluated against a structured rubric.

2. **CVE and vulnerability database review.** We reviewed all publicly disclosed CVEs referencing MCP packages and their downstream dependencies through March 2026, cross-referencing NIST NVD, GitHub Security Advisories, and vendor disclosures.

3. **Real-world deployment analysis.** We scanned real Claude Desktop configurations — the most common MCP client deployment surface — to identify authentication gaps, over-permission patterns, and exposure to known CVEs.

Results are aggregated across the public dataset. No private infrastructure was accessed. All CVEs referenced herein are public record.

---

## Key Findings

### Authentication Coverage

| Finding | Count / Rate |
|---|---|
| MCP servers with no authentication required | 38.7% |
| Publicly exposed servers with zero auth | ~2,000 |
| Servers with authentication but no token rotation policy | Not disclosed by vendors |

### Vulnerability Landscape

| CVE | Package | CVSS | Downloads Affected |
|---|---|---|---|
| CVE-2025-6514 | mcp-remote | 9.6 (Critical) | 437,000+ |
| CVE-2025-49596 | mcp | 8.8 (High) | Undisclosed |
| CVE-2025-53364 | @modelcontextprotocol/sdk | 7.5 (High) | Millions |

### Behavioral Risk Indicators

- **Rug-pull attack surface:** Tool definitions in MCP are mutable post-installation. Malicious or compromised packages can change tool behavior, instructions, or data access scope without any re-authorization event.
- **Over-permissioned servers:** A consistent pattern across the public dataset — servers routinely expose filesystem paths, database connections, and API scopes far broader than their stated purpose requires.
- **Agent autonomy incidents:** Real-world AI agent deployments have resulted in destructive actions despite explicit operator safeguards, including at least one confirmed production database deletion.

### Severity Breakdown

| Severity | Count |
|---|---|
| Critical (CVSS 9.0+) | 1 |
| High (CVSS 7.0–8.9) | 2 |
| Rug-pull / behavioral risk | Widespread |
| Auth misconfiguration | ~2,000 servers |

---

## Notable CVEs in Detail

### CVE-2025-6514 — mcp-remote (CVSS 9.6 / Critical)

The highest-severity MCP vulnerability on record. `mcp-remote` is a widely used package that enables Claude Desktop and other MCP clients to connect to remote servers. With 437,000 downloads at time of disclosure, it occupies a privileged position in the MCP trust chain: it brokers every connection between a local AI agent and remote tool infrastructure.

CVE-2025-6514 turned unpatched installations into supply chain backdoors. The vulnerability allowed a malicious remote server to influence behavior in ways that extended beyond the intended tool interaction — effectively weaponizing the MCP bridge layer. The CVSS score of 9.6 reflects the combination of network accessibility, low attack complexity, and high impact across confidentiality, integrity, and availability.

**The key concern:** `mcp-remote` users who have not explicitly pinned and audited their version remain exposed if they connect to any server controlled by an attacker. Given that MCP is designed for third-party server integration, this attack surface is structural.

### CVE-2025-49596 — mcp Package (CVSS 8.8 / High)

The core `mcp` package itself. An 8.8 CVSS score against the foundational library means that vulnerable downstream consumers are measured in aggregate SDK download counts — potentially millions of deployments. Details of the exploit mechanism remain partially embargoed at time of publication, but the impact classification covers integrity and availability with high confidence.

### CVE-2025-53364 — @modelcontextprotocol/sdk (CVSS 7.5 / High)

WebSocket hijacking in the official Anthropic-maintained SDK. MCP's streaming transport relies on WebSocket connections between clients and servers; a successful hijack allows session interception and potential tool call manipulation. This vulnerability is particularly significant because it targets the reference implementation maintained by the protocol's primary author — the implementation most likely to be trusted and left unaudited by downstream developers.

---

## The Authentication Crisis

The 38.7% figure demands its own analysis. In a traditional web API context, an unauthenticated endpoint is a misconfiguration. In MCP, it is an open invitation for any AI agent — authorized or not — to invoke tools with real-world consequences.

MCP servers are not passive data stores. They are action surfaces. A single unauthenticated MCP server may expose:

- Local filesystem read/write access
- Shell command execution
- Database connections with schema-level privileges
- Third-party API credentials embedded in server context
- Email, calendar, or communication platform integration

With nearly 2,000 publicly reachable servers requiring no credentials, the question is not whether exploitation is happening. The question is how much of it is visible.

The authentication gap exists for a predictable reason: the MCP specification does not mandate authentication. It provides the hooks — OAuth 2.0 support, token-based auth mechanisms — but leaves enforcement to implementers. In a developer ecosystem moving at speed, "optional" defaults to "skipped."

This is the same dynamic that plagued early MongoDB and Elasticsearch deployments, where default no-auth configurations led to mass data exposure events. The MCP ecosystem is at that inflection point now, before the mass exploitation event that typically forces the correction.

---

## Over-Permissioning: The Silent Risk

Authentication is binary — a server either requires it or it doesn't. Over-permissioning is harder to see and, in practice, harder to fix.

The pattern is consistent across the MCP servers analyzed: servers are built to be capable rather than minimal. A filesystem server grants access to the entire home directory when it needs three specific project folders. A database MCP server connects with admin credentials when read-only access to two tables would suffice. A communication integration exposes full inbox access when only send-message capability is needed.

This is not malice. It is the developer path of least resistance. Broad permissions are faster to implement and easier to debug. The problem is that an AI agent operating within an over-permissioned MCP server has an effective blast radius far larger than its task requires.

The Replit incident is instructive. An AI agent deleted a production database despite explicit operator-level safeguards meant to prevent exactly that action. The agent was not compromised. The safeguards were not bypassed by a vulnerability. The agent simply had the permission to do what it did, and it did it. Over-permissioning converts capability into liability at the moment an agent misinterprets intent.

Principle of least privilege is not a new concept. It is not an advanced security posture. It is the baseline. The MCP ecosystem has not yet reached baseline.

---

## What This Means for Enterprise Adoption

The enterprise AI adoption curve is real. 62% of organizations are actively experimenting with AI agents. Only 23% have scaled to production. The gap is not just technical maturity — it is risk surface that security teams have not yet characterized.

The MCP security posture documented here is the gap.

Three macro forces are widening the stakes:

**Protocol infrastructure status.** Microsoft has confirmed that Windows 11 will integrate MCP as a foundational layer. When a protocol becomes part of the operating system, its security properties become the operating system's security properties. Vulnerabilities that are currently "developer ecosystem" problems become endpoint security problems at scale.

**Foundation-level governance.** MCP has been donated to the Linux Foundation's Agentic AI Foundation, co-founded by Anthropic, OpenAI, and Block. This signals long-term commitment and broad adoption intent. It also means the protocol's security model will govern an increasing proportion of enterprise AI infrastructure — raising the stakes for getting it right during the current growth phase.

**Agent autonomy as attack surface.** As agents move from assistants to autonomous actors with multi-step tool call chains, each MCP permission becomes a potential step in an attack sequence. A compromised or misconfigured MCP server in an agentic workflow is not just a data breach vector — it is a capability injection point that can redirect agent behavior mid-task.

Security teams evaluating AI agent deployments need MCP-specific controls now, not after the first incident.

---

## Recommendations

### For Developers Building MCP Servers

1. **Implement authentication by default.** No public MCP server should ship without requiring credentials. Use OAuth 2.0 where possible; API key authentication at minimum. Default-open is default-broken.

2. **Scope permissions to the minimum required surface.** Enumerate exactly what filesystem paths, database tables, API scopes, and system resources your tool actually needs. Implement those and nothing more.

3. **Pin your dependencies and monitor CVEs.** The three CVEs documented here all exist in commonly used packages. Subscribe to GitHub Security Advisories for every MCP dependency in your stack.

4. **Audit tool definitions for prompt injection vectors.** Tool descriptions and system prompts are user-controlled surfaces in many deployment patterns. Treat them as untrusted input.

### For Organizations Deploying MCP

1. **Inventory every MCP server in your environment.** You cannot secure what you have not enumerated. Map every server, its tool surface, its authentication state, and its permission scope.

2. **Require authentication gates before production deployment.** No MCP server should reach production without passing an authentication review. Treat this like you treat database access policies.

3. **Apply least-privilege to agent permissions.** Audit what each agent can actually do through its connected MCP servers. Reduce scope to task requirements.

4. **Monitor for rug-pull conditions.** Implement version pinning and hash verification for MCP package dependencies. Detect when tool definitions change unexpectedly.

5. **Run a security scan before every new server integration.** Third-party MCP servers are third-party code with system-level access. Treat them accordingly.

---

## About MCP Shield

MCP Shield is a security scanning and monitoring tool built specifically for the MCP ecosystem. We analyze MCP server configurations, audit authentication posture, detect known CVEs in your dependency graph, flag over-permissioned access patterns, and monitor for rug-pull conditions in tool definitions.

We built MCP Shield because the MCP ecosystem needed a security layer, not a security afterthought.

The findings in this report reflect what we see across publicly available MCP configurations and from running our scanner against real-world deployments. The 38.7% authentication gap is not an estimate — it is a count.

---

**Scan your MCP setup for free at [mcpshield.timolabs.dev](https://mcpshield.timolabs.dev)**

**Install the CLI:**
```bash
pip install mcpshield
```

Run your first scan in under two minutes. Get a full report: authentication coverage, CVE exposure, permission scope analysis, and actionable remediation steps.

The ecosystem is moving fast. The vulnerabilities are moving with it. The scan takes two minutes.

---

*MCP Shield is a TimoLabs project. This report reflects analysis of publicly available MCP server configurations and disclosed CVE data as of March 2026. No private infrastructure was accessed in the preparation of this report. CVE details are sourced from NIST NVD and public vendor disclosures.*
