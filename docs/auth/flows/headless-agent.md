<!-- Licensed under CC-BY-4.0 -->

# SAFE-AUTH Flows — Headless Agent & Multi-Hop Delegation

This document complements the SAFE-AUTH overview with flows for **non-human agents** and **multi-hop delegation**.

## Headless Agent → MCP Server (OAuth2 Client Credentials + DPoP/mTLS)

```mermaid
sequenceDiagram
    participant Agent
    participant AS as Authorization Server
    participant Server as MCP Server/Tool
    Agent->>AS: client_credentials (DPoP/mTLS bound)
    AS-->>Agent: access_token (aud=Server)
    Agen

```mermaid
sequenceDiagram
    participant Agent
    participant AS as Authorization Server
    participant Server as MCP Server/Tool
    Agent->>AS: client_credentials (DPoP/mTLS bound)
    AS-->>Agent: access_token (aud=Server)
    Agent->>Server: Tool call (bound token, aud=Server)
    Server-->>Agent: Result (+ audit_id)

sequenceDiagram
    participant User
    participant AgentA
    participant AS as Authorization Server
    participant AgentB
    participant Tool
    User->>AgentA: Request action
    AgentA->>AS: Token Exchange (subject_token=user-bound; audience=AgentB)
    AS-->>AgentA: access_token (aud=AgentB)
    AgentA->>AgentB: Invoke (+ token aud=AgentB)
    AgentB->>AS: Token Exchange (subject_token=received; audience=Tool)
    AS-->>AgentB: access_token (aud=Tool)
    AgentB->>Tool: Tool call (+ token aud=Tool)
    Tool-->>AgentB: Result (+ telemetry)

