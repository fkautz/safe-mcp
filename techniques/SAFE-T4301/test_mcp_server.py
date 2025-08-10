#!/usr/bin/env python3
"""
Test MCP Server for SAFE-T4301 Testing

This creates a simple MCP server that you can use to test reconnaissance techniques.
Run this server and then practice the scanning techniques against it.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
import json
import asyncio
import uvicorn
import argparse
from typing import Any, Dict

app = FastAPI(title="Test MCP Server", description="MCP Server for Security Testing")

# Global session storage
sessions = {}

@app.get("/")
async def root():
    return {"message": "Test MCP Server", "protocol": "Model Context Protocol", "version": "2024-11-05"}

@app.get("/sse")
async def sse_endpoint():
    """Server-Sent Events endpoint for MCP communication"""
    
    # Generate a session ID
    import uuid
    session_id = str(uuid.uuid4())
    
    # Store session
    sessions[session_id] = {"active": True}
    
    async def event_stream():
        # Send the endpoint event with session URL
        endpoint_url = f"/messages?sessionId={session_id}"
        yield f"event: endpoint\ndata: {endpoint_url}\n\n"
        
        # Keep connection alive and handle any future messages
        while sessions.get(session_id, {}).get("active", False):
            await asyncio.sleep(1)
            # Send heartbeat
            yield f"event: heartbeat\ndata: {json.dumps({'timestamp': 'alive'})}\n\n"
    
    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        }
    )

@app.post("/messages")
async def handle_message(message: Dict[str, Any], sessionId: str = None):
    """Handle JSON-RPC messages from MCP clients"""
    
    if not sessionId or sessionId not in sessions:
        raise HTTPException(status_code=400, detail="Invalid session")
    
    # Handle different JSON-RPC methods
    method = message.get("method")
    msg_id = message.get("id")
    
    if method == "initialize":
        # Return server capabilities
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"subscribe": True, "listChanged": True}
                },
                "serverInfo": {
                    "name": "test-mcp-server",
                    "version": "1.0.0"
                }
            }
        }
        return response
    
    elif method == "notifications/initialized":
        # Acknowledge initialization
        return {"status": "initialized"}
    
    elif method == "tools/list":
        # Return available tools (this is what attackers enumerate)
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read contents of a file",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"}
                            },
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "list_directory", 
                        "description": "List directory contents",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"}
                            }
                        }
                    },
                    {
                        "name": "send_email",
                        "description": "Send an email message",
                        "inputSchema": {
                            "type": "object", 
                            "properties": {
                                "to": {"type": "string"},
                                "subject": {"type": "string"},
                                "body": {"type": "string"}
                            },
                            "required": ["to", "subject", "body"]
                        }
                    }
                ]
            }
        }
        return response
    
    else:
        # Unknown method
        raise HTTPException(status_code=400, detail=f"Unknown method: {method}")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "mcp-server"}

# Alternative endpoints that attackers might probe
@app.get("/mcp")
async def mcp_info():
    return {"protocol": "Model Context Protocol", "endpoints": ["/sse", "/messages"]}

@app.get("/api/mcp")
async def api_mcp():
    return {"error": "Use /sse endpoint for MCP communication"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test MCP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--log-level", default="info", help="Log level")
    
    args = parser.parse_args()
    
    print(f"🔍 Starting Test MCP Server for SAFE-T4301 Testing")
    print(f"📡 Server will be available at: http://{args.host}:{args.port}")
    print(f"🔗 MCP SSE Endpoint: http://{args.host}:{args.port}/sse")
    print(f"⚠️  WARNING: This server is for testing only - do not use in production!")
    print()
    
    uvicorn.run(
        app, 
        host=args.host, 
        port=args.port, 
        log_level=args.log_level
    )