# SAFE-T4301 Local Testing Guide

This guide shows you how to test the MCP Server Fingerprinting and Enumeration technique on your local machine.

## Prerequisites

Install required Python packages:

```bash
pip install fastapi uvicorn requests
```

## Test Setup Options

### Option 1: Quick Detection Test

Test the detection logic with sample data:

```bash
cd techniques/SAFE-T4301
python3 test_detection_rule.py
```

This will:
- ✅ Analyze 10 sample log entries
- ✅ Detect 7 suspicious activities (70% detection rate)
- ✅ Validate all expected attack patterns

### Option 2: Full Reconnaissance Simulation

#### Step 1: Start the Test MCP Server

In Terminal 1, start the vulnerable test server:

```bash
cd techniques/SAFE-T4301
python3 test_mcp_server.py --port 8000
```

You should see:
```
🔍 Starting Test MCP Server for SAFE-T4301 Testing
📡 Server will be available at: http://0.0.0.0:8000
🔗 MCP SSE Endpoint: http://0.0.0.0:8000/sse
⚠️  WARNING: This server is for testing only - do not use in production!
```

#### Step 2: Test Single Target Reconnaissance

In Terminal 2, run reconnaissance against your test server:

```bash
cd techniques/SAFE-T4301
python3 test_reconnaissance.py --target http://localhost:8000
```

Expected output:
```
🔒 SAFE-T4301: MCP Server Reconnaissance Testing
⚠️  WARNING: Only use this on systems you own or have permission to test!

🔍 Fingerprinting: http://localhost:8000
  ✓ Found SSE endpoint with correct content-type
  ✓ Response follows SSE format
  ✓ Found MCP indicators in /
  ✓ Successful MCP handshake at /messages
    Server: test-mcp-server v1.0.0
✅ Confirmed MCP server at http://localhost:8000
🔧 Enumerating tools...
  📋 Found 3 tools:
    - read_file: Read contents of a file
    - list_directory: List directory contents
    - send_email: Send an email message
📋 Found 3 tools available

📊 Results for http://localhost:8000:
  MCP Server: Yes
  Tools Found: 3
```

#### Step 3: Test Network Scanning

Test scanning a local network range (this will only find your test server):

```bash
python3 test_reconnaissance.py --scan 127.0.0.0/24 --ports 8000
```

## Manual Testing with curl

You can also manually test the techniques using curl:

### 1. SSE Endpoint Discovery
```bash
curl -H "Accept: text/event-stream" http://localhost:8000/sse
```

### 2. JSON-RPC Handshake
```bash
curl -X POST http://localhost:8000/messages?sessionId=test \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "test-client", "version": "1.0"}
    },
    "id": 1
  }'
```

### 3. Tool Enumeration
```bash
curl -X POST http://localhost:8000/messages?sessionId=test \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 2
  }'
```

## Testing with Sigma Rules

### Option 1: Convert to Real SIEM

Take the `detection-rule.yml` and:

1. **For Splunk**: Convert using sigmac:
   ```bash
   pip install sigmatools
   sigmac -t splunk detection-rule.yml
   ```

2. **For Elastic**: Convert using sigma:
   ```bash
   sigmac -t elasticsearch detection-rule.yml
   ```

### Option 2: Log Analysis

Generate realistic logs and test detection:

```bash
# Start the test server with logging
python3 test_mcp_server.py --log-level debug 2>&1 | tee server.log

# In another terminal, run reconnaissance
python3 test_reconnaissance.py --target http://localhost:8000

# Check the logs for attack patterns
grep -E "(GET /sse|jsonrpc|tools/list)" server.log
```

## Advanced Testing Scenarios

### 1. Multiple Servers

Start servers on different ports:
```bash
python3 test_mcp_server.py --port 8000 &
python3 test_mcp_server.py --port 8080 &
python3 test_mcp_server.py --port 3000 &

# Scan for all of them
python3 test_reconnaissance.py --scan 127.0.0.0/24 --ports 8000,8080,3000
```

### 2. Rate Limiting Test

Test how detection works under rate limiting:
```bash
# Add delays between requests
for i in {1..10}; do
  curl http://localhost:8000/sse
  sleep 1
done
```

### 3. User Agent Variation

Test different scanning signatures:
```bash
# Simulate different tools
curl -H "User-Agent: masscan/1.0.5" http://localhost:8000/mcp
curl -H "User-Agent: nmap NSE" http://localhost:8000/api/mcp
curl -H "User-Agent: python-requests/2.31.0" http://localhost:8000/sse
```

## Monitoring and Detection

While testing, monitor for these indicators:

1. **Network Traffic**: Watch for systematic scanning patterns
2. **Log Patterns**: Look for the attack signatures in your logs
3. **Behavioral Analysis**: Notice the sequence of SSE → handshake → enumeration

## Cleanup

When done testing:

```bash
# Kill any running test servers
pkill -f test_mcp_server.py

# Clean up any generated files
rm -f server.log *.pyc
```

## Real-World Application

To apply this in your environment:

1. **Deploy the Sigma Rule**: Import `detection-rule.yml` into your SIEM
2. **Network Monitoring**: Set up alerts for systematic port scanning
3. **Rate Limiting**: Implement rate limits on MCP endpoints
4. **Authentication**: Add authentication to prevent unauthorized enumeration

## Troubleshooting

### Server Won't Start
```bash
# Check if port is in use
lsof -i :8000

# Use different port
python3 test_mcp_server.py --port 8001
```

### Python Dependencies
```bash
# Install missing packages
pip install fastapi uvicorn requests asyncio

# Or use virtual environment
python3 -m venv test_env
source test_env/bin/activate
pip install fastapi uvicorn requests
```

### Permission Issues
```bash
# If scanning localhost fails
sudo python3 test_reconnaissance.py --scan 127.0.0.0/24
```

This testing setup gives you a complete lab environment to understand how MCP reconnaissance works and how to detect it effectively.