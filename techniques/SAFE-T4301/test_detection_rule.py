#!/usr/bin/env python3
"""
SAFE-T4301: MCP Server Fingerprinting and Enumeration - Detection Test Script

This script tests the detection rule against sample log data to validate
the effectiveness of the SIGMA rule for identifying MCP reconnaissance activities.
"""

import json
import re
from typing import Dict, List, Any


class MCPFingerprintingDetector:
    """Detector for MCP Server Fingerprinting and Enumeration attacks"""
    
    def __init__(self):
        # Detection patterns based on the SIGMA rule
        self.sse_patterns = {
            'uri_contains': ['/sse'],
            'methods': ['GET']
        }
        
        self.jsonrpc_patterns = [
            r'"jsonrpc":"2\.0"',
            r'"method":"initialize"',
            r'"protocolVersion"'
        ]
        
        self.tools_patterns = [
            r'"method":"tools/list"'
        ]
        
        self.scanning_user_agents = [
            'masscan',
            'nmap',
            'python-requests',
            'curl'
        ]
        
        self.scanning_uris = [
            '/mcp',
            '/api/mcp',
            '/messages'
        ]
    
    def detect_sse_reconnaissance(self, log_entry: Dict[str, Any]) -> bool:
        """Detect SSE endpoint reconnaissance attempts"""
        uri = log_entry.get('request_uri', '')
        method = log_entry.get('http_method', '')
        
        return (any(pattern in uri for pattern in self.sse_patterns['uri_contains']) and
                method in self.sse_patterns['methods'])
    
    def detect_jsonrpc_probing(self, log_entry: Dict[str, Any]) -> bool:
        """Detect JSON-RPC initialization probing"""
        request_body = log_entry.get('request_body', '')
        
        if not request_body:
            return False
            
        return any(re.search(pattern, request_body) for pattern in self.jsonrpc_patterns)
    
    def detect_tools_enumeration(self, log_entry: Dict[str, Any]) -> bool:
        """Detect MCP tools enumeration attempts"""
        request_body = log_entry.get('request_body', '')
        
        if not request_body:
            return False
            
        return any(re.search(pattern, request_body) for pattern in self.tools_patterns)
    
    def detect_scanning_activity(self, log_entry: Dict[str, Any]) -> bool:
        """Detect general scanning activity targeting MCP endpoints"""
        user_agent = log_entry.get('user_agent', '').lower()
        uri = log_entry.get('request_uri', '')
        
        # Check for suspicious user agents
        suspicious_ua = any(agent in user_agent for agent in self.scanning_user_agents)
        
        # Check for MCP-related URIs
        mcp_uri = any(pattern in uri for pattern in self.scanning_uris)
        
        return suspicious_ua and mcp_uri
    
    def analyze_log_entry(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single log entry for MCP fingerprinting indicators"""
        results = {
            'timestamp': log_entry.get('timestamp'),
            'src_ip': log_entry.get('src_ip'),
            'uri': log_entry.get('request_uri'),
            'method': log_entry.get('http_method'),
            'user_agent': log_entry.get('user_agent'),
            'detections': []
        }
        
        # Run all detection methods
        if self.detect_sse_reconnaissance(log_entry):
            results['detections'].append('SSE_RECONNAISSANCE')
        
        if self.detect_jsonrpc_probing(log_entry):
            results['detections'].append('JSONRPC_PROBING')
        
        if self.detect_tools_enumeration(log_entry):
            results['detections'].append('TOOLS_ENUMERATION')
        
        if self.detect_scanning_activity(log_entry):
            results['detections'].append('SCANNING_ACTIVITY')
        
        results['is_suspicious'] = len(results['detections']) > 0
        
        return results
    
    def analyze_log_file(self, log_file_path: str) -> List[Dict[str, Any]]:
        """Analyze a JSON log file for MCP fingerprinting activities"""
        results = []
        
        with open(log_file_path, 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    analysis = self.analyze_log_entry(log_entry)
                    results.append(analysis)
                except json.JSONDecodeError:
                    continue
        
        return results


def main():
    """Main function to test the detection logic"""
    detector = MCPFingerprintingDetector()
    
    # Test with the sample log file
    log_file = 'test-logs.json'
    
    try:
        results = detector.analyze_log_file(log_file)
        
        print("=== MCP Fingerprinting Detection Results ===\n")
        
        suspicious_count = 0
        total_count = len(results)
        
        for result in results:
            if result['is_suspicious']:
                suspicious_count += 1
                print(f"🚨 SUSPICIOUS ACTIVITY DETECTED")
                print(f"   Timestamp: {result['timestamp']}")
                print(f"   Source IP: {result['src_ip']}")
                print(f"   URI: {result['uri']}")
                print(f"   Method: {result['method']}")
                print(f"   User Agent: {result['user_agent']}")
                print(f"   Detections: {', '.join(result['detections'])}")
                print()
            else:
                print(f"✅ Normal activity: {result['src_ip']} -> {result['uri']}")
        
        print(f"\n=== Summary ===")
        print(f"Total log entries analyzed: {total_count}")
        print(f"Suspicious activities detected: {suspicious_count}")
        print(f"Detection rate: {(suspicious_count/total_count)*100:.1f}%")
        
        # Expected detections based on test data
        expected_detections = [
            'SSE_RECONNAISSANCE',      # python-requests to /sse
            'JSONRPC_PROBING',         # JSON-RPC initialize request
            'TOOLS_ENUMERATION',       # tools/list request
            'SCANNING_ACTIVITY',       # masscan user agent
            'SCANNING_ACTIVITY'        # nmap user agent
        ]
        
        all_detections = []
        for result in results:
            all_detections.extend(result['detections'])
        
        print(f"\nDetection types found: {set(all_detections)}")
        print(f"Expected detection types: {set(expected_detections)}")
        
        if set(all_detections) >= set(expected_detections):
            print("✅ All expected attack patterns were detected!")
        else:
            print("⚠️  Some expected attack patterns were not detected.")
        
    except FileNotFoundError:
        print(f"Error: Could not find log file '{log_file}'")
        print("Please ensure the test-logs.json file exists in the same directory.")
    except Exception as e:
        print(f"Error during analysis: {e}")


if __name__ == "__main__":
    main()