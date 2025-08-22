# SAFE-T4301: MCP Server Fingerprinting and Enumeration

## Overview
**Tactic**: Reconnaissance (ATK-TA0043)  
**Technique ID**: SAFE-T4301  
**Severity**: Medium  
**First Observed**: July 2025 (Research by Knostic Team and HiddenLayer)  
**Last Updated**: 2025-01-15

## Description
MCP Server Fingerprinting and Enumeration is a reconnaissance technique where adversaries systematically identify and map exposed Model Context Protocol (MCP) servers across networks to gather intelligence about target environments. Attackers use specialized scanning tools and fingerprinting methods to discover MCP services, enumerate their capabilities, and identify potential attack vectors without directly interacting with the services.

This technique leverages the distinctive characteristics of MCP servers, including their protocol markers, transport signatures, and endpoint patterns, to build comprehensive intelligence about an organization's MCP deployment. The information gathered forms the foundation for subsequent attack phases.

## Attack Vectors
- **Primary Vector**: Internet-wide scanning using tools like Shodan, Masscan, and custom fingerprinting scripts
- **Secondary Vectors**: 
  - Network enumeration within compromised environments
  - DNS reconnaissance to discover MCP-related subdomains and services
  - Port scanning with MCP-specific service detection scripts
  - Social engineering to obtain information about internal MCP deployments
  - Supply chain analysis to identify organizations using specific MCP implementations

## Technical Details

### Prerequisites
- Network access to target ranges (internet or internal networks)
- Knowledge of MCP protocol characteristics and common deployment patterns
- Access to scanning tools (Shodan, Masscan, Nmap, custom scripts)
- Understanding of MCP transport mechanisms (SSE, STDIO)

### Attack Flow
1. **Target Identification**: Identify potential target IP ranges, organizations, or domains likely to use MCP services
2. **Port Discovery**: Scan common ports (8000, 8080, 3000, 5000, 9090, 80) for HTTP services
3. **Protocol Fingerprinting**: Send HTTP requests to identify MCP-specific characteristics:
   - `GET /sse` requests looking for `text/event-stream` content type
   - JSON-RPC initialization handshakes with MCP protocol markers
   - Detection of Server-Sent Events (SSE) endpoints
4. **Service Enumeration**: For confirmed MCP servers, enumerate available tools and capabilities:
   - Send `tools/list` requests to catalog available functions
   - Extract server metadata and version information
   - Identify vendor-specific implementations and customizations
5. **Intelligence Gathering**: Analyze discovered servers to understand:
   - Organizational attack surface and technology stack
   - Potential high-value targets (databases, cloud services, file systems)
   - Security posture and access controls
6. **Documentation**: Catalog findings for future exploitation phases

### Example Scenario
```bash
# Shodan query to find exposed MCP servers
shodan search 'http.html:"jsonrpc" content:"text/event-stream"'

# Custom fingerprinting with multiple detection vectors
nmap --script http-enum --script-args http-enum.basepath=/mcp -p 8000,8080 target-range

# MCP-specific handshake attempt
curl -X POST http://target:8080/sse \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"scanner","version":"1.0"}},"id":1}'
```

### Advanced Attack Techniques (2025 Research)

According to research from [Knostic Team](https://www.knostic.ai/blog/mapping-mcp-servers-study) and [HiddenLayer](https://hiddenlayer.com/innovation-hub/mcp-model-context-pitfalls-in-an-agentic-world/), attackers have developed sophisticated fingerprinting methods:

1. **Multi-Vector Protocol Detection**: Using combinations of HTTP headers, SSE endpoints, and JSON-RPC patterns to increase detection accuracy ([Knostic, 2025](https://www.knostic.ai/blog/find-mcp-server-shodan))
2. **Framework-Specific Fingerprinting**: Identifying underlying technologies like FastAPI/Uvicorn through server headers combined with MCP markers
3. **Endpoint Path Enumeration**: Scanning for common paths like `/mcp`, `/messages`, `/api/mcp` to find non-standard deployments

## Impact Assessment
- **Confidentiality**: Medium - Reveals organizational technology stack and potential attack vectors
- **Integrity**: Low - Reconnaissance phase typically doesn't modify systems
- **Availability**: Low - Scanning activities generally don't disrupt services
- **Scope**: Network-wide - Can map entire organizational MCP infrastructure

### Current Status (2025)
According to security researchers, the MCP reconnaissance threat is actively developing:
- Knostic discovered 1,862 MCP servers exposed to the internet with 119 manually verified as unauthenticated
- HiddenLayer found 55 unique servers across 187 instances through Shodan searches
- All discovered servers lacked authentication and exposed tool listings to anyone with protocol knowledge

## Detection Methods

### Indicators of Compromise (IoCs)
- High-volume HTTP requests to MCP-related ports (8000, 8080, 3000, 5000, 9090)
- HTTP requests to `/sse` endpoints with suspicious User-Agent strings
- JSON-RPC initialization attempts from unexpected source IPs
- Systematic enumeration of tools via `tools/list` requests
- Port scans targeting MCP-specific port ranges

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Attackers continuously develop new scanning techniques and evasion methods. Organizations should:
- Use behavioral analysis to identify scanning patterns
- Monitor for unusual traffic volumes to MCP endpoints
- Implement rate limiting and access controls
- Consider network segmentation for MCP services

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: MCP Server Fingerprinting Activity
id: 7a8b9c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d
status: experimental
description: Detects potential MCP server reconnaissance and fingerprinting attempts
author: SAFE-MCP Research Team
date: 2025-01-15
references:
  - https://github.com/safe-mcp/techniques/SAFE-T4301
logsource:
  product: webserver
  service: http_access_logs
detection:
  selection_sse:
    request_uri|contains: '/sse'
    http_method: 'GET'
  selection_jsonrpc:
    request_body|contains:
      - '"jsonrpc":"2.0"'
      - '"method":"initialize"'
      - '"protocolVersion"'
  selection_tools:
    request_body|contains:
      - '"method":"tools/list"'
  selection_scanning:
    user_agent|contains:
      - 'masscan'
      - 'nmap'
      - 'python-requests'
      - 'curl'
    request_uri|contains:
      - '/mcp'
      - '/api/mcp'
      - '/messages'
  condition: selection_sse or selection_jsonrpc or selection_tools or selection_scanning
falsepositives:
  - Legitimate MCP client connections
  - Authorized penetration testing
  - Network monitoring tools
level: medium
tags:
  - attack.reconnaissance
  - attack.t1046
  - safe.t4301
```

### Behavioral Indicators
- Sequential port scanning targeting MCP-specific ports
- Systematic enumeration of multiple MCP servers within short time frames
- Unusual geographic origins for MCP protocol requests
- Failed authentication attempts followed by protocol fingerprinting

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-1: Network Segmentation](../../mitigations/SAFE-M-1/README.md)**: Isolate MCP services behind firewalls and limit external exposure
2. **[SAFE-M-2: Authentication and Access Control](../../mitigations/SAFE-M-2/README.md)**: Implement strong authentication for all MCP endpoints to prevent unauthorized enumeration
3. **[SAFE-M-3: Service Hardening](../../mitigations/SAFE-M-3/README.md)**: Configure MCP servers to minimize information disclosure and bind to specific interfaces only

### Detective Controls
1. **[SAFE-M-4: Network Monitoring](../../mitigations/SAFE-M-4/README.md)**: Deploy intrusion detection systems to monitor for reconnaissance activities
2. **[SAFE-M-5: Rate Limiting](../../mitigations/SAFE-M-5/README.md)**: Implement rate limiting on MCP endpoints to slow reconnaissance attempts

### Response Procedures
1. **Immediate Actions**:
   - Block suspicious IP addresses conducting reconnaissance
   - Review and tighten access controls on exposed MCP services
   - Assess whether enumerated services contain sensitive capabilities
2. **Investigation Steps**:
   - Analyze logs to determine scope of reconnaissance activity
   - Identify which MCP servers and tools were enumerated
   - Check for signs of follow-up exploitation attempts
3. **Remediation**:
   - Move exposed MCP services behind authentication layers
   - Implement network segmentation to limit reconnaissance scope
   - Update monitoring rules based on observed attack patterns

## Related Techniques
- [SAFE-T1601](../SAFE-T1601/README.md): MCP Server Enumeration (post-access discovery)
- [SAFE-T1007](../SAFE-T1007/README.md): OAuth Authorization Phishing (exploitation following reconnaissance)
- [SAFE-T1001](../SAFE-T1001/README.md): Tool Poisoning Attack (exploitation of discovered servers)

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [Knostic Team - Mapping MCP Servers Across the Internet](https://www.knostic.ai/blog/mapping-mcp-servers-study)
- [Knostic Team - How to Find an MCP Server with Shodan](https://www.knostic.ai/blog/find-mcp-server-shodan)
- [HiddenLayer - MCP Model Context Pitfalls in an Agentic World](https://hiddenlayer.com/innovation-hub/mcp-model-context-pitfalls-in-an-agentic-world/)
- [Masscan - Fast Port Scanner](https://github.com/robertdavidgraham/masscan)
- [Shodan - Internet-wide Scanning Service](https://www.shodan.io)

## MITRE ATT&CK Mapping
- [T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-01-15 | Initial documentation | SAFE-MCP Research Team |