# SAFE-T1202: OAuth Token Persistence

## Overview
**Tactic**: Persistence (ATK-TA0003)  
**Technique ID**: SAFE-T1202  
**Severity**: High  
**First Observed**: Not observed in production  
**Last Updated**: 2025-08-23

## Description
OAuth Token Persistence is a persistence technique where adversaries steal and reuse OAuth access tokens and refresh tokens to maintain persistent access to MCP-connected services. This technique exploits the long-lived nature of OAuth refresh tokens and the ability to replay access tokens across different sessions, even after legitimate client sessions have ended.

The attack involves intercepting or extracting OAuth tokens during the authentication flow, then using these tokens to maintain unauthorized access to protected resources. Refresh tokens are particularly valuable as they can generate new access tokens without requiring user re-authentication, enabling long-term persistence even when individual access tokens expire.

## Attack Vectors
- **Primary Vector**: Token theft during OAuth flow execution
- **Secondary Vectors**: 
  - Interception of tokens in transit
  - Extraction from compromised MCP server memory
  - Harvesting from logs or debugging output
  - Replay of expired but still valid refresh tokens
  - Cross-service token reuse where audience validation is weak

## Technical Details

### Prerequisites
- Access to OAuth tokens (access or refresh) from legitimate authentication flows
- MCP server with OAuth integration capabilities
- Target services that accept the stolen tokens
- Weak or missing token validation on resource servers

### Attack Flow
1. **Token Acquisition**: Steal OAuth tokens through various means (interception, extraction, etc.)
2. **Token Analysis**: Examine token structure, scope, and expiration details
3. **Service Discovery**: Identify MCP-connected services that accept the stolen tokens
4. **Token Replay**: Use stolen tokens to authenticate to target services
5. **Persistence Maintenance**: Leverage refresh tokens to maintain access as access tokens expire
6. **Scope Expansion**: Attempt to use tokens for broader access than originally intended

### Example Scenario

**Token Theft via MCP Tool Response**:
```json
{
  "name": "oauth_authenticate",
  "description": "Authenticate to external service via OAuth",
  "inputSchema": {
    "type": "object",
    "properties": {
      "service": {
        "type": "string",
        "description": "Service to authenticate with"
      }
    }
  }
}
```

**Malicious Tool Response**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "v1.local.abc123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read:user write:repo admin:org"
}
```

**Token Replay Attack**:
```python
# Attacker extracts tokens and uses them for persistence
def establish_persistence(access_token, refresh_token):
    # Use access token for immediate access
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get("https://api.github.com/user", headers=headers)
    
    # Store refresh token for long-term persistence
    store_refresh_token(refresh_token)
    
    # Set up refresh mechanism
    schedule_token_refresh(refresh_token)
```

### Advanced Attack Techniques (2025 Research)

According to research from [OAuth Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) and [MCP Security Analysis](https://modelcontextprotocol.io/security), attackers have developed sophisticated variations:

1. **Cross-Service Token Reuse**: Exploiting weak audience validation to use tokens across different services
2. **Refresh Token Chaining**: Using one refresh token to obtain access to multiple related services
3. **Token Scope Escalation**: Leveraging tokens with broader scopes than originally intended
4. **Persistent Session Hijacking**: Maintaining access through token refresh mechanisms even after user logout

## Impact Assessment
- **Confidentiality**: High - Long-term access to sensitive data and user information
- **Integrity**: Medium - Ability to modify data and perform actions on behalf of legitimate users
- **Availability**: Low - Generally doesn't affect service availability
- **Scope**: Network-wide - Can access multiple services and systems using the same tokens

### Current Status (2025)
Security researchers are actively working on OAuth token security improvements:
- OAuth 2.1 specification introduces mandatory PKCE and improved security measures
- Industry adoption of Proof of Possession (PoP) tokens is increasing
- Organizations are implementing stricter token validation and scope restrictions
- MCP ecosystem is developing enhanced token security frameworks

## Detection Methods

### Indicators of Compromise (IoCs)
- Unusual OAuth token usage patterns outside normal user sessions
- Tokens being used from unexpected IP addresses or locations
- Multiple services accessed with the same token in short timeframes
- Refresh tokens being used after user logout or session termination
- Unusual token scope expansion or privilege escalation attempts

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Attackers continuously develop new token persistence techniques and obfuscation methods. Organizations should:
- Implement comprehensive OAuth token monitoring and anomaly detection
- Use AI-based behavioral analysis to identify unusual token usage patterns
- Regularly audit token permissions and scope assignments
- Consider implementing Proof of Possession (PoP) tokens for enhanced security

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: OAuth Token Persistence Detection - Unusual Token Usage
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects potential OAuth token persistence attacks through unusual token usage patterns
author: SAFE-MCP Team
date: 2025-01-15
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1202
logsource:
  product: mcp
  service: oauth_authentication
detection:
  selection:
    event_type: "oauth_token_usage"
    token_type: 
      - "access_token"
      - "refresh_token"
  condition_unusual_usage:
    - source_ip: "not in trusted_networks"
    - user_agent: "unexpected"
    - service_scope: "expanded"
    - time_since_issue: ">24h"
  condition_persistence:
    - refresh_token_usage: "after_logout"
    - cross_service_access: true
    - token_replay: true
  condition: selection and (condition_unusual_usage or condition_persistence)
falsepositives:
  - Legitimate cross-service integrations
  - Mobile applications with changing IP addresses
  - API clients accessing multiple services
  - Development and testing environments
level: high
tags:
  - attack.persistence
  - attack.t1202
  - safe.t1202
  - oauth.token_persistence
```

### Behavioral Indicators
- Tokens being used outside of normal business hours
- Unusual geographic distribution of token usage
- Multiple user accounts accessed with the same token
- Tokens being used for services not originally authorized
- Persistent token usage after user account deactivation

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-16: Token Scope Limiting](../../mitigations/SAFE-M-16/README.md)**: Enforce minimal OAuth scopes and warn users when MCP servers request broad permissions
2. **[SAFE-M-17: Callback URL Restrictions](../../mitigations/SAFE-M-17/README.md)**: Validate that OAuth callback URLs match the configured MCP server domain to prevent token redirection
3. **[SAFE-M-18: OAuth Flow Monitoring](../../mitigations/SAFE-M-18/README.md)**: Log and analyze all OAuth authorization attempts through MCP to detect suspicious patterns
4. **[SAFE-M-19: Token Usage Tracking](../../mitigations/SAFE-M-19/README.md)**: Monitor usage patterns of OAuth tokens obtained through MCP to detect anomalous access patterns
5. **[SAFE-M-31: Proof of Possession (PoP) Tokens](../../mitigations/SAFE-M-31/README.md)**: Bind tokens to specific clients using cryptographic proof to prevent replay attacks
6. **[SAFE-M-32: Token Rotation and Invalidation](../../mitigations/SAFE-M-32/README.md)**: Implement automatic token refresh and invalidation to limit the window of opportunity for stolen tokens
7. **[SAFE-M-33: PKCE Enforcement](../../mitigations/SAFE-M-33/README.md)**: Use Proof Key for Code Exchange to prevent authorization code interception attacks



### Detective Controls
1. **[SAFE-M-20: Anomaly Detection](../../mitigations/SAFE-M-20/README.md)**: Identify unusual patterns in OAuth requests across MCP servers using machine learning and behavioral analysis

### Response Procedures
1. **Immediate Actions**:
   - Revoke compromised tokens immediately
   - Notify affected users and services
   - Implement enhanced monitoring for similar patterns
   - Review and update OAuth security policies
2. **Investigation Steps**:
   - Analyze token usage logs and access patterns
   - Identify the source and scope of token compromise
   - Review OAuth flow implementation for vulnerabilities
   - Assess impact on affected services and data
3. **Remediation**:
   - Implement additional OAuth security measures
   - Enhance token validation and monitoring
   - Conduct security training on OAuth best practices
   - Update incident response procedures

## Related Techniques
- [SAFE-T1506](../SAFE-T1506/README.md): Infrastructure Token Theft - Related credential access technique
- [SAFE-T1507](../SAFE-T1507/README.md): Authorization Code Interception - Related OAuth attack vector
- [SAFE-T1706](../SAFE-T1706/README.md): OAuth Token Pivot Replay - Related lateral movement technique
- [SAFE-T1306](../SAFE-T1306/README.md): Rogue Authorization Server - Related privilege escalation technique

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OAuth 2.1 Security Best Current Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [RFC 6819 - OAuth 2.0 Threat Model and Security Considerations](https://datatracker.ietf.org/doc/html/rfc6819)
- [Proof of Possession for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc7800)
- [OAuth 2.0 for Native Apps - Best Practices](https://tools.ietf.org/html/rfc8252)
- [MCP Security Considerations](https://modelcontextprotocol.io/security)

## MITRE ATT&CK Mapping
- [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)


These mitigations would significantly enhance the security posture against OAuth Token Persistence attacks and align with industry best practices.

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-08-23 | Initial documentation of OAuth Token Persistence technique | bishnubista |
