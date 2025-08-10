#!/usr/bin/env python3
"""
SAFE-T4301: MCP Reconnaissance Testing Script

This script demonstrates the reconnaissance techniques described in SAFE-T4301.
Use this to practice and understand how attackers discover and enumerate MCP servers.

USAGE:
    python3 test_reconnaissance.py --target http://localhost:8000
    python3 test_reconnaissance.py --scan 192.168.1.0/24
"""

import requests
import socket
import json
import argparse
import sys
from urllib.parse import urljoin
import time
from typing import List, Dict, Any
import ipaddress
import concurrent.futures
from dataclasses import dataclass

@dataclass
class ScanResult:
    host: str
    port: int
    is_mcp: bool
    server_info: Dict[str, Any] = None
    tools: List[Dict[str, Any]] = None
    error: str = None

class MCPReconnaissanceScanner:
    """Implements the reconnaissance techniques from SAFE-T4301"""
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'MCP-Security-Scanner/1.0'
        })
    
    def check_port_open(self, host: str, port: int) -> bool:
        """Check if a port is open using TCP connect"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def fingerprint_mcp_server(self, base_url: str) -> ScanResult:
        """Fingerprint a potential MCP server using multiple detection methods"""
        
        print(f"🔍 Fingerprinting: {base_url}")
        
        # Parse host and port for result
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        result = ScanResult(host=host, port=port, is_mcp=False)
        
        # Method 1: Check for SSE endpoint
        sse_indicators = self.check_sse_endpoint(base_url)
        
        # Method 2: Look for MCP-specific endpoints
        endpoint_indicators = self.check_mcp_endpoints(base_url)
        
        # Method 3: Try JSON-RPC handshake
        jsonrpc_indicators = self.check_jsonrpc_handshake(base_url)
        
        # Determine if this is likely an MCP server
        total_indicators = sum([
            len(sse_indicators),
            len(endpoint_indicators), 
            len(jsonrpc_indicators)
        ])
        
        if total_indicators >= 2:
            result.is_mcp = True
            print(f"✅ Confirmed MCP server at {base_url}")
            
            # If confirmed, try to enumerate tools
            tools = self.enumerate_tools(base_url)
            if tools:
                result.tools = tools
                print(f"📋 Found {len(tools)} tools available")
        else:
            print(f"❌ Not an MCP server: {base_url}")
        
        return result
    
    def check_sse_endpoint(self, base_url: str) -> List[str]:
        """Check for Server-Sent Events endpoint (Step 1 of fingerprinting)"""
        indicators = []
        
        try:
            # Try GET /sse
            sse_url = urljoin(base_url, '/sse')
            response = self.session.get(sse_url, timeout=self.timeout, stream=True)
            
            # Check for SSE content type
            content_type = response.headers.get('content-type', '')
            if 'text/event-stream' in content_type:
                indicators.append('sse_content_type')
                print(f"  ✓ Found SSE endpoint with correct content-type")
            
            # Check for SSE event format in response
            if response.status_code == 200:
                # Read a small amount of response to check format
                for line in response.iter_lines(decode_unicode=True):
                    if line and ('event:' in line or 'data:' in line):
                        indicators.append('sse_format')
                        print(f"  ✓ Response follows SSE format")
                        break
                    if len(indicators) > 0:  # Don't read too much
                        break
            
        except Exception as e:
            pass
        
        return indicators
    
    def check_mcp_endpoints(self, base_url: str) -> List[str]:
        """Check for common MCP endpoint paths (Step 2 of fingerprinting)"""
        indicators = []
        
        # Common MCP endpoint paths from research
        endpoints_to_check = [
            '/mcp',
            '/api/mcp', 
            '/messages',
            '/'
        ]
        
        for endpoint in endpoints_to_check:
            try:
                url = urljoin(base_url, endpoint)
                response = self.session.get(url, timeout=self.timeout)
                
                # Check response content for MCP indicators
                if response.status_code == 200:
                    content = response.text.lower()
                    if any(indicator in content for indicator in [
                        'model context protocol',
                        'mcp',
                        'jsonrpc',
                        'protocol'
                    ]):
                        indicators.append(f'mcp_endpoint_{endpoint.replace("/", "_")}')
                        print(f"  ✓ Found MCP indicators in {endpoint}")
                        
            except Exception:
                continue
        
        return indicators
    
    def check_jsonrpc_handshake(self, base_url: str) -> List[str]:
        """Attempt JSON-RPC MCP handshake (Step 3 of fingerprinting)"""
        indicators = []
        
        # Try the standard MCP initialization handshake
        handshake_payload = {
            "jsonrpc": "2.0",
            "method": "initialize", 
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "reconnaissance-scanner",
                    "version": "1.0.0"
                }
            },
            "id": 1
        }
        
        # Try different possible endpoints
        endpoints_to_try = ['/messages', '/mcp', '/api/mcp', '/jsonrpc']
        
        for endpoint in endpoints_to_try:
            try:
                url = urljoin(base_url, endpoint)
                response = self.session.post(
                    url,
                    json=handshake_payload,
                    timeout=self.timeout,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if (data.get('jsonrpc') == '2.0' and 
                            'result' in data and
                            'serverInfo' in data.get('result', {})):
                            indicators.append('jsonrpc_handshake_success')
                            print(f"  ✓ Successful MCP handshake at {endpoint}")
                            
                            # Store server info
                            server_info = data.get('result', {}).get('serverInfo', {})
                            if server_info:
                                print(f"    Server: {server_info.get('name', 'unknown')} v{server_info.get('version', 'unknown')}")
                    except json.JSONDecodeError:
                        pass
                        
            except Exception:
                continue
        
        return indicators
    
    def enumerate_tools(self, base_url: str) -> List[Dict[str, Any]]:
        """Enumerate available tools on confirmed MCP server"""
        
        print(f"🔧 Enumerating tools...")
        
        # First, we need to establish a session through SSE
        try:
            # Get SSE endpoint to establish session
            sse_url = urljoin(base_url, '/sse')
            response = self.session.get(sse_url, timeout=self.timeout, stream=True)
            
            session_url = None
            for line in response.iter_lines(decode_unicode=True):
                if line.startswith('data:'):
                    data = line[5:].strip()  # Remove 'data:' prefix
                    if data.startswith('/messages'):
                        session_url = urljoin(base_url, data)
                        break
            
            if not session_url:
                print("  ❌ Could not establish session")
                return []
            
            # Send tools/list request
            tools_payload = {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 2
            }
            
            response = self.session.post(
                session_url,
                json=tools_payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                tools = data.get('result', {}).get('tools', [])
                
                print(f"  📋 Found {len(tools)} tools:")
                for tool in tools:
                    print(f"    - {tool.get('name', 'unnamed')}: {tool.get('description', 'no description')}")
                
                return tools
            
        except Exception as e:
            print(f"  ❌ Tool enumeration failed: {e}")
        
        return []
    
    def scan_ip_range(self, ip_range: str, ports: List[int] = None) -> List[ScanResult]:
        """Scan an IP range for MCP servers"""
        
        if ports is None:
            ports = [8000, 8080, 3000, 5000, 9090, 80, 443]
        
        print(f"🌐 Scanning IP range: {ip_range}")
        print(f"🔍 Checking ports: {ports}")
        
        # Parse IP range
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            print(f"❌ Invalid IP range: {ip_range}")
            return []
        
        results = []
        total_targets = len(list(network.hosts())) * len(ports)
        
        print(f"📊 Total targets to scan: {total_targets}")
        
        # Use threading for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            
            for ip in network.hosts():
                for port in ports:
                    if self.check_port_open(str(ip), port):
                        # Port is open, test for MCP
                        scheme = 'https' if port == 443 else 'http'
                        base_url = f"{scheme}://{ip}:{port}"
                        future = executor.submit(self.fingerprint_mcp_server, base_url)
                        futures.append(future)
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    print(f"❌ Error scanning target: {e}")
        
        return results

def main():
    parser = argparse.ArgumentParser(
        description="MCP Server Reconnaissance Testing Tool (SAFE-T4301)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test a specific MCP server
  python3 test_reconnaissance.py --target http://localhost:8000
  
  # Scan a local network range
  python3 test_reconnaissance.py --scan 192.168.1.0/24
  
  # Scan with custom ports
  python3 test_reconnaissance.py --scan 10.0.0.0/24 --ports 8000,8080,3000
        """
    )
    
    parser.add_argument('--target', help='Target a specific URL for MCP fingerprinting')
    parser.add_argument('--scan', help='Scan an IP range (CIDR notation)')
    parser.add_argument('--ports', help='Comma-separated list of ports to scan (default: 8000,8080,3000,5000,9090,80,443)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds')
    
    args = parser.parse_args()
    
    if not args.target and not args.scan:
        parser.print_help()
        sys.exit(1)
    
    # Parse ports
    ports = [8000, 8080, 3000, 5000, 9090, 80, 443]
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("❌ Invalid port format. Use comma-separated integers.")
            sys.exit(1)
    
    scanner = MCPReconnaissanceScanner(timeout=args.timeout)
    
    print("🔒 SAFE-T4301: MCP Server Reconnaissance Testing")
    print("⚠️  WARNING: Only use this on systems you own or have permission to test!")
    print()
    
    if args.target:
        # Single target fingerprinting
        result = scanner.fingerprint_mcp_server(args.target)
        
        print(f"\n📊 Results for {args.target}:")
        print(f"  MCP Server: {'Yes' if result.is_mcp else 'No'}")
        if result.tools:
            print(f"  Tools Found: {len(result.tools)}")
        
    elif args.scan:
        # Network range scanning
        results = scanner.scan_ip_range(args.scan, ports)
        
        print(f"\n📊 Scan Results:")
        mcp_servers = [r for r in results if r.is_mcp]
        
        print(f"  Total MCP servers found: {len(mcp_servers)}")
        
        for result in mcp_servers:
            print(f"  🎯 {result.host}:{result.port}")
            if result.tools:
                print(f"     Tools: {len(result.tools)}")

if __name__ == "__main__":
    main()