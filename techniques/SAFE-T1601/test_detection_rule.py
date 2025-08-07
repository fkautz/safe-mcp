#!/usr/bin/env python3
"""
Test script for SAFE-T1601 MCP Server Enumeration detection rule validation.

This script validates that our detection rule correctly identifies MCP enumeration
activities from the test log data.
"""

import json
import re
from datetime import datetime
from typing import List, Dict, Any

class MCPEnumerationDetector:
    """Detector for MCP Server Enumeration activities based on SAFE-T1601 rule."""
    
    def __init__(self):
        self.mcp_ports = [8000, 8080, 3000, 5000, 9090, 80]
        self.mcp_endpoints = ['/sse', '/message']
        self.mcp_methods = ['tools/list', 'resources/list', 'prompts/list', 'initialize']
        self.scanning_user_agents = ['masscan', 'nmap', 'curl', 'wget', 'python-requests']
        
    def detect_port_scanning(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect network-level MCP port scanning."""
        detections = []
        
        # Group events by source IP and time window
        source_connections = {}
        
        for event in events:
            if event.get('event_type') == 'network_connection':
                source_ip = event.get('source_ip')
                dest_port = event.get('destination_port')
                
                if dest_port in self.mcp_ports:
                    if source_ip not in source_connections:
                        source_connections[source_ip] = []
                    source_connections[source_ip].append(event)
        
        # Check for high-volume scanning
        for source_ip, connections in source_connections.items():
            if len(connections) > 5:  # Threshold for suspicious activity
                detections.append({
                    'detection_type': 'mcp_port_scanning',
                    'source_ip': source_ip,
                    'connection_count': len(connections),
                    'targeted_ports': list(set([c['destination_port'] for c in connections])),
                    'severity': 'high',
                    'description': f'High-volume scanning of MCP ports from {source_ip}'
                })
                
        return detections
    
    def detect_http_enumeration(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect HTTP-level MCP endpoint enumeration."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'http_request':
                uri = event.get('uri', '')
                response_headers = event.get('response_headers', '')
                
                # Check for MCP endpoint access
                if any(endpoint in uri for endpoint in self.mcp_endpoints):
                    if 'text/event-stream' in response_headers:
                        detections.append({
                            'detection_type': 'mcp_endpoint_discovery',
                            'source_ip': event.get('source_ip'),
                            'target': f"{event.get('destination_ip')}:{event.get('destination_port')}",
                            'endpoint': uri,
                            'severity': 'medium',
                            'description': f'MCP SSE endpoint discovered: {uri}'
                        })
        
        return detections
    
    def detect_protocol_enumeration(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect MCP protocol-level enumeration."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'mcp_protocol':
                request_body = event.get('request_body', '')
                
                # Parse JSON-RPC method if present
                try:
                    if '"method"' in request_body:
                        for method in self.mcp_methods:
                            if f'"{method}"' in request_body:
                                detections.append({
                                    'detection_type': 'mcp_protocol_enumeration',
                                    'source_ip': event.get('source_ip'),
                                    'target': f"{event.get('destination_ip')}:{event.get('destination_port')}",
                                    'method': method,
                                    'severity': 'high',
                                    'description': f'MCP enumeration method detected: {method}'
                                })
                except:
                    pass  # Skip malformed JSON
        
        return detections
    
    def detect_automated_scanning(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect automated scanning tools."""
        detections = []
        
        for event in events:
            user_agent = event.get('user_agent', '').lower()
            
            # Check for scanning tool user agents
            for scanner in self.scanning_user_agents:
                if scanner in user_agent:
                    detections.append({
                        'detection_type': 'automated_scanning_tool',
                        'source_ip': event.get('source_ip'),
                        'user_agent': event.get('user_agent'),
                        'tool': scanner,
                        'severity': 'high',
                        'description': f'Automated scanning tool detected: {scanner}'
                    })
                    break
        
        return detections
    
    def detect_dns_rebinding(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect DNS rebinding attack patterns."""
        detections = []
        
        # Track DNS queries by domain
        dns_queries = {}
        
        for event in events:
            if event.get('event_type') == 'dns_query':
                domain = event.get('query_name')
                response = event.get('response')
                
                if domain not in dns_queries:
                    dns_queries[domain] = []
                dns_queries[domain].append(response)
        
        # Check for resolution changes to localhost
        for domain, responses in dns_queries.items():
            unique_responses = list(set(responses))
            localhost_ips = ['127.0.0.1', '0.0.0.0', 'localhost']
            
            if len(unique_responses) > 1 and any(ip in localhost_ips for ip in unique_responses):
                detections.append({
                    'detection_type': 'dns_rebinding_attack',
                    'domain': domain,
                    'responses': unique_responses,
                    'severity': 'critical',
                    'description': f'DNS rebinding detected for domain {domain}'
                })
        
        return detections
    
    def analyze_logs(self, log_file: str) -> Dict[str, Any]:
        """Analyze log file for MCP enumeration activities."""
        try:
            with open(log_file, 'r') as f:
                events = json.load(f)
        except Exception as e:
            return {'error': f'Failed to load log file: {e}'}
        
        all_detections = []
        
        # Run all detection methods
        all_detections.extend(self.detect_port_scanning(events))
        all_detections.extend(self.detect_http_enumeration(events))
        all_detections.extend(self.detect_protocol_enumeration(events))
        all_detections.extend(self.detect_automated_scanning(events))
        all_detections.extend(self.detect_dns_rebinding(events))
        
        # Categorize by severity
        critical = [d for d in all_detections if d.get('severity') == 'critical']
        high = [d for d in all_detections if d.get('severity') == 'high']
        medium = [d for d in all_detections if d.get('severity') == 'medium']
        
        return {
            'total_events': len(events),
            'total_detections': len(all_detections),
            'detections': {
                'critical': critical,
                'high': high,
                'medium': medium
            },
            'summary': {
                'critical_count': len(critical),
                'high_count': len(high),
                'medium_count': len(medium),
                'detection_types': list(set([d['detection_type'] for d in all_detections]))
            }
        }

def main():
    """Main function to test MCP enumeration detection."""
    detector = MCPEnumerationDetector()
    
    # Test with our sample log data
    log_file = 'test-logs.json'
    results = detector.analyze_logs(log_file)
    
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
        return
    
    print("🔍 SAFE-T1601 MCP Server Enumeration Detection Results")
    print("=" * 60)
    print(f"📊 Total Events Analyzed: {results['total_events']}")
    print(f"🚨 Total Detections: {results['total_detections']}")
    print()
    
    summary = results['summary']
    print("📈 Detection Summary:")
    print(f"  🔴 Critical: {summary['critical_count']}")
    print(f"  🟠 High: {summary['high_count']}")
    print(f"  🟡 Medium: {summary['medium_count']}")
    print()
    
    print("🎯 Detection Types Found:")
    for detection_type in summary['detection_types']:
        print(f"  • {detection_type}")
    print()
    
    # Show detailed detections
    detections = results['detections']
    
    if detections['critical']:
        print("🔴 CRITICAL SEVERITY DETECTIONS:")
        for detection in detections['critical']:
            print(f"  ⚠️  {detection['description']}")
        print()
    
    if detections['high']:
        print("🟠 HIGH SEVERITY DETECTIONS:")
        for detection in detections['high']:
            print(f"  ⚠️  {detection['description']}")
        print()
    
    if detections['medium']:
        print("🟡 MEDIUM SEVERITY DETECTIONS:")
        for detection in detections['medium']:
            print(f"  ⚠️  {detection['description']}")
        print()
    
    # Validate expected detections
    expected_types = [
        'mcp_port_scanning',
        'mcp_endpoint_discovery', 
        'mcp_protocol_enumeration',
        'automated_scanning_tool',
        'dns_rebinding_attack'
    ]
    
    found_types = summary['detection_types']
    missing_types = [t for t in expected_types if t not in found_types]
    
    if missing_types:
        print(f"⚠️  Missing expected detection types: {missing_types}")
    else:
        print("✅ All expected detection types found!")
    
    print("\n🎉 Detection rule validation complete!")

if __name__ == '__main__':
    main()
