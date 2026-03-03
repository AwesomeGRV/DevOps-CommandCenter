#!/usr/bin/env python3
"""
Network Policy Analyzer
Author: DevOps-CommandCenter
Description: Analyze Kubernetes network policies and security posture
"""

import kubernetes
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class NetworkPolicyIssue:
    namespace: str
    policy_name: str
    issue_type: str
    severity: str
    description: str
    affected_pods: List[str]
    recommendation: str

class NetworkPolicyAnalyzer:
    def __init__(self):
        kubernetes.config.load_kube_config()
        self.v1 = kubernetes.client.CoreV1Api()
        self.networking_v1 = kubernetes.client.NetworkingV1Api()
        self.policy_issues = []
    
    def analyze_network_policies(self, namespace: str = None) -> List[NetworkPolicyIssue]:
        """Analyze network policies across namespaces"""
        self.policy_issues = []
        
        # Get all namespaces
        namespaces = self._get_namespaces(namespace)
        
        for ns in namespaces:
            try:
                self._analyze_namespace_policies(ns)
            except Exception as e:
                logger.error(f"Error analyzing namespace {ns}: {str(e)}")
        
        return self.policy_issues
    
    def _get_namespaces(self, namespace_filter: str = None) -> List[str]:
        """Get namespaces to analyze"""
        if namespace_filter:
            return [namespace_filter]
        
        try:
            namespaces = self.v1.list_namespace()
            return [ns.metadata.name for ns in namespaces.items]
        except Exception as e:
            logger.error(f"Error getting namespaces: {str(e)}")
            return []
    
    def _analyze_namespace_policies(self, namespace: str):
        """Analyze policies in a specific namespace"""
        # Get network policies
        policies = self.networking_v1.list_namespaced_network_policy(namespace)
        
        # Get pods in namespace
        pods = self.v1.list_namespaced_pod(namespace)
        
        # Get services in namespace
        services = self.v1.list_namespaced_service(namespace)
        
        # Check for missing policies
        self._check_missing_policies(namespace, pods.items, policies.items)
        
        # Analyze existing policies
        for policy in policies.items:
            self._analyze_policy(namespace, policy, pods.items, services.items)
        
        # Check for overly permissive policies
        self._check_permissive_policies(namespace, policies.items)
        
        # Check for policy conflicts
        self._check_policy_conflicts(namespace, policies.items)
    
    def _check_missing_policies(self, namespace: str, pods: List, policies: List):
        """Check for pods without network policies"""
        if not policies:
            # No policies at all - all pods are exposed
            issue = NetworkPolicyIssue(
                namespace=namespace,
                policy_name="NO_POLICIES",
                issue_type="no_network_policies",
                severity="critical",
                description="No network policies defined in namespace",
                affected_pods=[pod.metadata.name for pod in pods],
                recommendation="Create default deny policy and specific allow policies"
            )
            self.policy_issues.append(issue)
            return
        
        # Check which pods are covered by policies
        covered_pods = set()
        for policy in policies:
            pod_selector = policy.spec.pod_selector
            for pod in pods:
                if self._pod_matches_selector(pod, pod_selector):
                    covered_pods.add(pod.metadata.name)
        
        # Find uncovered pods
        uncovered_pods = [pod.metadata.name for pod in pods if pod.metadata.name not in covered_pods]
        
        if uncovered_pods:
            issue = NetworkPolicyIssue(
                namespace=namespace,
                policy_name="UNCOVERED_PODS",
                issue_type="uncovered_pods",
                severity="high",
                description=f"Pods without network policy coverage: {', '.join(uncovered_pods)}",
                affected_pods=uncovered_pods,
                recommendation="Create network policies to cover all pods or use default deny policy"
            )
            self.policy_issues.append(issue)
    
    def _analyze_policy(self, namespace: str, policy, pods: List, services: List):
        """Analyze individual network policy"""
        policy_name = policy.metadata.name
        
        # Check policy selector
        if not policy.spec.pod_selector.match_labels and not policy.spec.pod_selector.match_expressions:
            issue = NetworkPolicyIssue(
                namespace=namespace,
                policy_name=policy_name,
                issue_type="empty_selector",
                severity="medium",
                description="Policy has empty pod selector - affects all pods in namespace",
                affected_pods=[pod.metadata.name for pod in pods],
                recommendation="Specify explicit pod selector to limit policy scope"
            )
            self.policy_issues.append(issue)
        
        # Check ingress rules
        if policy.spec.ingress:
            for i, rule in enumerate(policy.spec.ingress):
                self._analyze_ingress_rule(namespace, policy_name, i, rule, pods, services)
        
        # Check egress rules
        if policy.spec.egress:
            for i, rule in enumerate(policy.spec.egress):
                self._analyze_egress_rule(namespace, policy_name, i, rule, pods, services)
        
        # Check for unused policies
        affected_pods = [pod.metadata.name for pod in pods 
                        if self._pod_matches_selector(pod, policy.spec.pod_selector)]
        
        if not affected_pods:
            issue = NetworkPolicyIssue(
                namespace=namespace,
                policy_name=policy_name,
                issue_type="unused_policy",
                severity="low",
                description="Policy doesn't match any pods in namespace",
                affected_pods=[],
                recommendation="Remove unused policy or fix pod selector"
            )
            self.policy_issues.append(issue)
    
    def _analyze_ingress_rule(self, namespace: str, policy_name: str, 
                             rule_index: int, rule, pods: List, services: List):
        """Analyze ingress rule"""
        # Check for overly broad ingress
        if not rule.from_:
            issue = NetworkPolicyIssue(
                namespace=namespace,
                policy_name=policy_name,
                issue_type="broad_ingress",
                severity="high",
                description=f"Rule {rule_index} allows ingress from any source",
                affected_pods=[],
                recommendation="Specify source selectors or namespaces for ingress rules"
            )
            self.policy_issues.append(issue)
            return
        
        # Check each from clause
        for from_clause in rule.from_:
            if from_clause.namespace_selector and not from_clause.pod_selector:
                # Namespace selector without pod selector - allows all pods in namespace
                issue = NetworkPolicyIssue(
                    namespace=namespace,
                    policy_name=policy_name,
                    issue_type="broad_namespace_selector",
                    severity="medium",
                    description=f"Rule {rule_index} allows all pods from selected namespace",
                    affected_pods=[],
                    recommendation="Add pod selector to namespace selector or use specific pod selectors"
                )
                self.policy_issues.append(issue)
            
            # Check for port ranges
            if rule.ports:
                for port in rule.ports:
                    if port.end_port and port.end_port - port.port > 1000:
                        issue = NetworkPolicyIssue(
                            namespace=namespace,
                            policy_name=policy_name,
                            issue_type="wide_port_range",
                            severity="medium",
                            description=f"Rule {rule_index} allows wide port range: {port.port}-{port.end_port}",
                            affected_pods=[],
                            recommendation="Use specific ports instead of wide ranges"
                        )
                        self.policy_issues.append(issue)
    
    def _analyze_egress_rule(self, namespace: str, policy_name: str, 
                            rule_index: int, rule, pods: List, services: List):
        """Analyze egress rule"""
        # Check for overly broad egress
        if not rule.to:
            issue = NetworkPolicyIssue(
                namespace=namespace,
                policy_name=policy_name,
                issue_type="broad_egress",
                severity="high",
                description=f"Rule {rule_index} allows egress to any destination",
                affected_pods=[],
                recommendation="Specify destination selectors for egress rules"
            )
            self.policy_issues.append(issue)
            return
        
        # Check for external access
        external_access = False
        for to_clause in rule.to:
            if not to_clause.namespace_selector and not to_clause.pod_selector and not to_clause.ip_block:
                external_access = True
                break
        
        if external_access:
            issue = NetworkPolicyIssue(
                namespace=namespace,
                policy_name=policy_name,
                issue_type="external_access",
                severity="medium",
                description=f"Rule {rule_index} allows external network access",
                affected_pods=[],
                recommendation="Restrict external access or use specific IP blocks"
            )
            self.policy_issues.append(issue)
    
    def _check_permissive_policies(self, namespace: str, policies: List):
        """Check for overly permissive policies"""
        for policy in policies:
            policy_name = policy.metadata.name
            
            # Check for allow-all ingress
            if policy.spec.ingress:
                for rule in policy.spec.ingress:
                    if not rule.from_ and not rule.ports:
                        issue = NetworkPolicyIssue(
                            namespace=namespace,
                            policy_name=policy_name,
                            issue_type="allow_all_ingress",
                            severity="critical",
                            description="Policy allows all ingress traffic",
                            affected_pods=[],
                            recommendation="Restrict ingress to specific sources and ports"
                        )
                        self.policy_issues.append(issue)
            
            # Check for allow-all egress
            if policy.spec.egress:
                for rule in policy.spec.egress:
                    if not rule.to and not rule.ports:
                        issue = NetworkPolicyIssue(
                            namespace=namespace,
                            policy_name=policy_name,
                            issue_type="allow_all_egress",
                            severity="critical",
                            description="Policy allows all egress traffic",
                            affected_pods=[],
                            recommendation="Restrict egress to specific destinations and ports"
                        )
                        self.policy_issues.append(issue)
    
    def _check_policy_conflicts(self, namespace: str, policies: List):
        """Check for conflicting policies"""
        # This is a simplified check - in practice, would need more sophisticated analysis
        policy_map = defaultdict(list)
        
        for policy in policies:
            selector = policy.spec.pod_selector
            for pod_key in self._selector_to_keys(selector):
                policy_map[pod_key].append(policy.metadata.name)
        
        # Check for overlapping policies
        for pod_key, policy_names in policy_map.items():
            if len(policy_names) > 1:
                issue = NetworkPolicyIssue(
                    namespace=namespace,
                    policy_name="POLICY_OVERLAP",
                    issue_type="policy_overlap",
                    severity="medium",
                    description=f"Multiple policies apply to same pods: {', '.join(policy_names)}",
                    affected_pods=[pod_key],
                    recommendation="Review overlapping policies for potential conflicts"
                )
                self.policy_issues.append(issue)
    
    def _pod_matches_selector(self, pod, selector) -> bool:
        """Check if pod matches selector"""
        if not selector.match_labels and not selector.match_expressions:
            return True  # Empty selector matches all
        
        # Check label matching
        if selector.match_labels:
            pod_labels = pod.metadata.labels or {}
            for key, value in selector.match_labels.items():
                if pod_labels.get(key) != value:
                    return False
        
        # Check expression matching (simplified)
        if selector.match_expressions:
            pod_labels = pod.metadata.labels or {}
            for expression in selector.match_expressions:
                key = expression.key
                operator = expression.operator
                values = expression.values or []
                
                if operator == 'Exists':
                    if key not in pod_labels:
                        return False
                elif operator == 'DoesNotExist':
                    if key in pod_labels:
                        return False
                elif operator == 'In':
                    if pod_labels.get(key) not in values:
                        return False
                elif operator == 'NotIn':
                    if pod_labels.get(key) in values:
                        return False
        
        return True
    
    def _selector_to_keys(self, selector) -> List[str]:
        """Convert selector to list of possible pod keys"""
        # Simplified - in practice, would generate all possible combinations
        if selector.match_labels:
            return [f"{k}={v}" for k, v in selector.match_labels.items()]
        return ["*"]
    
    def generate_report(self, issues: List[NetworkPolicyIssue]) -> Dict[str, Any]:
        """Generate network policy analysis report"""
        # Group by severity
        severity_counts = defaultdict(int)
        for issue in issues:
            severity_counts[issue.severity] += 1
        
        # Group by namespace
        namespace_counts = defaultdict(int)
        for issue in issues:
            namespace_counts[issue.namespace] += 1
        
        # Group by issue type
        type_counts = defaultdict(int)
        for issue in issues:
            type_counts[issue.issue_type] += 1
        
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_issues": len(issues),
                "severity_breakdown": dict(severity_counts),
                "namespace_breakdown": dict(namespace_counts),
                "issue_type_breakdown": dict(type_counts)
            },
            "issues": [asdict(issue) for issue in issues],
            "recommendations": self._generate_recommendations(issues),
            "security_score": self._calculate_security_score(issues)
        }
    
    def _generate_recommendations(self, issues: List[NetworkPolicyIssue]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Critical issues
        critical_issues = [i for i in issues if i.severity == 'critical']
        if critical_issues:
            recommendations.append("URGENT: Address critical network policy issues immediately")
        
        # Common recommendations based on issue types
        issue_types = set(i.issue_type for i in issues)
        
        if 'no_network_policies' in issue_types:
            recommendations.append("Implement network policies in all namespaces")
        
        if 'uncovered_pods' in issue_types:
            recommendations.append("Ensure all pods are covered by network policies")
        
        if 'allow_all_ingress' in issue_types or 'allow_all_egress' in issue_types:
            recommendations.append("Remove overly permissive allow-all policies")
        
        if 'broad_ingress' in issue_types or 'broad_egress' in issue_types:
            recommendations.append("Use specific source/destination selectors instead of broad rules")
        
        # General recommendations
        recommendations.extend([
            "Implement default deny policies in all namespaces",
            "Use namespace-specific policies for isolation",
            "Regularly review and audit network policies",
            "Test network policies in staging before production",
            "Monitor network traffic to validate policy effectiveness"
        ])
        
        return recommendations
    
    def _calculate_security_score(self, issues: List[NetworkPolicyIssue]) -> float:
        """Calculate network security score"""
        if not issues:
            return 100.0
        
        # Weight issues by severity
        severity_weights = {
            'critical': 10,
            'high': 5,
            'medium': 2,
            'low': 1
        }
        
        total_weight = sum(severity_weights.get(issue.severity, 1) for issue in issues)
        
        # Calculate score (100 is perfect, lower is worse)
        score = max(0, 100 - total_weight)
        
        return score

def main():
    parser = argparse.ArgumentParser(description='Analyze Kubernetes network policies')
    parser.add_argument('--namespace', help='Specific namespace to analyze')
    parser.add_argument('--output', default='network_policy_analysis.json')
    
    args = parser.parse_args()
    
    try:
        analyzer = NetworkPolicyAnalyzer()
        issues = analyzer.analyze_network_policies(args.namespace)
        report = analyzer.generate_report(issues)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Network Policy Analysis Summary:")
        print(f"Total issues: {report['summary']['total_issues']}")
        print(f"Critical: {report['summary']['severity_breakdown'].get('critical', 0)}")
        print(f"High: {report['summary']['severity_breakdown'].get('high', 0)}")
        print(f"Medium: {report['summary']['severity_breakdown'].get('medium', 0)}")
        print(f"Low: {report['summary']['severity_breakdown'].get('low', 0)}")
        print(f"Security Score: {report['security_score']:.1f}/100")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error during network policy analysis: {str(e)}")

if __name__ == "__main__":
    main()
