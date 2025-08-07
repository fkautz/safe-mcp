#!/usr/bin/env python3
"""
Test script for SAFE-T1703 Tool-Chaining Pivot detection rule validation.

This script validates that our detection rule correctly identifies tool-chaining
pivot attacks used for lateral movement in MCP environments.
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Set

class ToolChainingPivotDetector:
    """Detector for Tool-Chaining Pivot attacks based on SAFE-T1703 rule."""
    
    def __init__(self):
        self.privilege_escalation_patterns = [
            'low_to_medium', 'medium_to_high', 'low_to_high'
        ]
        self.admin_tools = ['admin_', 'system_', 'execute_', 'manage_']
        self.basic_tools = ['_reader', '_access', '_basic']
        self.sensitive_data_types = [
            'commands', 'credentials', 'configuration', 
            'admin_instructions', 'system_calls'
        ]
        
    def detect_privilege_escalation(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect tool execution with privilege escalation patterns."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'tool_execution':
                privilege_change = event.get('privilege_change')
                execution_method = event.get('execution_method')
                chain_length = event.get('chain_length', 0)
                
                if (privilege_change in self.privilege_escalation_patterns and 
                    execution_method == 'indirect' and chain_length > 1):
                    
                    detections.append({
                        'detection_type': 'privilege_escalation_via_chaining',
                        'tool': event.get('tool_name'),
                        'privilege_change': privilege_change,
                        'chain_length': chain_length,
                        'severity': 'high',
                        'timestamp': event.get('timestamp'),
                        'description': f'Privilege escalation detected: {privilege_change} via tool chain'
                    })
        
        return detections
    
    def detect_tool_chaining(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual tool interaction patterns indicating chaining."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'tool_interaction':
                source_tool = event.get('source_tool', '')
                dest_tool = event.get('destination_tool', '')
                interaction_type = event.get('interaction_type')
                
                # Check for basic-to-admin tool interactions
                source_is_basic = any(pattern in source_tool for pattern in self.basic_tools)
                dest_is_admin = any(pattern in dest_tool for pattern in self.admin_tools)
                
                if (source_is_basic and dest_is_admin and 
                    interaction_type in ['data_transfer', 'command_passing']):
                    
                    detections.append({
                        'detection_type': 'suspicious_tool_chaining',
                        'source_tool': source_tool,
                        'destination_tool': dest_tool,
                        'interaction_type': interaction_type,
                        'severity': 'high',
                        'timestamp': event.get('timestamp'),
                        'description': f'Suspicious tool chain: {source_tool} -> {dest_tool}'
                    })
        
        return detections
    
    def detect_suspicious_data_flow(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect suspicious data flow between privilege levels."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'data_transfer':
                source_priv = event.get('source_privilege')
                dest_priv = event.get('destination_privilege')
                data_type = event.get('data_type')
                validated = event.get('validated', True)
                
                if (source_priv == 'low' and dest_priv == 'high' and 
                    data_type in self.sensitive_data_types and not validated):
                    
                    detections.append({
                        'detection_type': 'suspicious_data_flow',
                        'source_privilege': source_priv,
                        'destination_privilege': dest_priv,
                        'data_type': data_type,
                        'validated': validated,
                        'severity': 'critical',
                        'timestamp': event.get('timestamp'),
                        'description': f'Unvalidated {data_type} flowing from {source_priv} to {dest_priv} privilege'
                    })
        
        return detections
    
    def detect_automated_chaining(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect rapid tool succession indicating automated chaining."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'tool_sequence':
                tool_count = event.get('tool_count', 0)
                time_window = event.get('time_window', 0)
                privilege_progression = event.get('privilege_progression')
                user_interaction = event.get('user_interaction', True)
                
                if (tool_count > 3 and time_window < 300 and  # Less than 5 minutes
                    privilege_progression == 'ascending' and not user_interaction):
                    
                    detections.append({
                        'detection_type': 'automated_tool_chaining',
                        'tool_count': tool_count,
                        'time_window': time_window,
                        'tools_sequence': event.get('tools_sequence', []),
                        'severity': 'high',
                        'timestamp': event.get('timestamp'),
                        'description': f'Automated tool chain with {tool_count} tools in {time_window}s'
                    })
        
        return detections
    
    def detect_context_pollution(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect context pollution attacks."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'context_modification':
                modification_type = event.get('modification_type')
                affected_tools = event.get('affected_tools', 0)
                persistence = event.get('persistence', False)
                
                dangerous_modifications = [
                    'privilege_injection', 'trust_elevation', 'session_hijack'
                ]
                
                if (modification_type in dangerous_modifications and 
                    affected_tools > 1 and persistence):
                    
                    detections.append({
                        'detection_type': 'context_pollution_attack',
                        'modification_type': modification_type,
                        'affected_tools': affected_tools,
                        'persistence': persistence,
                        'severity': 'critical',
                        'timestamp': event.get('timestamp'),
                        'description': f'Context pollution: {modification_type} affecting {affected_tools} tools'
                    })
        
        return detections
    
    def detect_trust_abuse(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect trust relationship exploitation."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'trust_validation':
                validation_result = event.get('validation_result')
                trust_source = event.get('trust_source')
                method = event.get('method')
                
                if (validation_result == 'bypassed' and 
                    'compromised' in trust_source.lower()):
                    
                    detections.append({
                        'detection_type': 'trust_relationship_abuse',
                        'trust_source': trust_source,
                        'method': method,
                        'bypass_technique': event.get('bypass_technique'),
                        'severity': 'high',
                        'timestamp': event.get('timestamp'),
                        'description': f'Trust bypass detected: {method} from {trust_source}'
                    })
        
        return detections
    
    def detect_resource_pivoting(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect resource-based pivoting attacks."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'resource_access':
                access_pattern = event.get('access_pattern')
                resource_privilege = event.get('resource_privilege')
                tool_privilege = event.get('tool_privilege')
                pivot_indicator = event.get('pivot_indicator', False)
                
                if (access_pattern == 'cross_privilege' and 
                    resource_privilege == 'admin' and 
                    tool_privilege == 'basic' and pivot_indicator):
                    
                    detections.append({
                        'detection_type': 'resource_pivoting_attack',
                        'accessing_tool': event.get('accessing_tool'),
                        'resource_type': event.get('resource_type'),
                        'privilege_mismatch': f'{tool_privilege} -> {resource_privilege}',
                        'severity': 'high',
                        'timestamp': event.get('timestamp'),
                        'description': f'Resource pivoting: {tool_privilege} tool accessing {resource_privilege} resource'
                    })
        
        return detections
    
    def detect_advanced_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect advanced attack patterns."""
        detections = []
        
        for event in events:
            event_type = event.get('event_type')
            
            # Parallel chain attacks
            if event_type == 'parallel_chain_attack':
                concurrent_chains = event.get('concurrent_chains', 0)
                if concurrent_chains > 1:
                    detections.append({
                        'detection_type': 'parallel_chain_attack',
                        'concurrent_chains': concurrent_chains,
                        'convergence_point': event.get('convergence_point'),
                        'severity': 'critical',
                        'timestamp': event.get('timestamp'),
                        'description': f'Parallel chain attack with {concurrent_chains} concurrent chains'
                    })
            
            # Recursive exploitation
            elif event_type == 'recursive_exploitation':
                if event.get('escalation_loop', False):
                    detections.append({
                        'detection_type': 'recursive_exploitation',
                        'tool_name': event.get('tool_name'),
                        'loop_count': event.get('loop_count'),
                        'privilege_amplification': event.get('privilege_amplification'),
                        'severity': 'critical',
                        'timestamp': event.get('timestamp'),
                        'description': f'Recursive privilege escalation loop detected'
                    })
        
        return detections
    
    def analyze_logs(self, log_file: str) -> Dict[str, Any]:
        """Analyze log file for tool-chaining pivot activities."""
        try:
            with open(log_file, 'r') as f:
                events = json.load(f)
        except Exception as e:
            return {'error': f'Failed to load log file: {e}'}
        
        all_detections = []
        
        # Run all detection methods
        all_detections.extend(self.detect_privilege_escalation(events))
        all_detections.extend(self.detect_tool_chaining(events))
        all_detections.extend(self.detect_suspicious_data_flow(events))
        all_detections.extend(self.detect_automated_chaining(events))
        all_detections.extend(self.detect_context_pollution(events))
        all_detections.extend(self.detect_trust_abuse(events))
        all_detections.extend(self.detect_resource_pivoting(events))
        all_detections.extend(self.detect_advanced_patterns(events))
        
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
    """Main function to test tool-chaining pivot detection."""
    detector = ToolChainingPivotDetector()
    
    # Test with our sample log data
    log_file = 'test-logs.json'
    results = detector.analyze_logs(log_file)
    
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
        return
    
    print("🔗 SAFE-T1703 Tool-Chaining Pivot Detection Results")
    print("=" * 65)
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
        'privilege_escalation_via_chaining',
        'suspicious_tool_chaining',
        'suspicious_data_flow',
        'automated_tool_chaining',
        'context_pollution_attack',
        'trust_relationship_abuse',
        'resource_pivoting_attack',
        'parallel_chain_attack',
        'recursive_exploitation'
    ]
    
    found_types = summary['detection_types']
    missing_types = [t for t in expected_types if t not in found_types]
    
    if missing_types:
        print(f"⚠️  Missing expected detection types: {missing_types}")
    else:
        print("✅ All expected detection types found!")
    
    # Additional analysis
    print(f"\n📊 Attack Pattern Analysis:")
    escalation_detections = [d for d in results['detections']['high'] + results['detections']['critical'] 
                           if 'escalation' in d['detection_type']]
    chaining_detections = [d for d in results['detections']['high'] + results['detections']['critical'] 
                          if 'chaining' in d['detection_type']]
    
    print(f"  🔺 Privilege Escalation Attacks: {len(escalation_detections)}")
    print(f"  ⛓️  Tool Chaining Attacks: {len(chaining_detections)}")
    
    print("\n🎉 Detection rule validation complete!")

if __name__ == '__main__':
    main()
