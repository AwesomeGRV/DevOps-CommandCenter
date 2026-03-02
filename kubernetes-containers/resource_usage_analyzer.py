#!/usr/bin/env python3
"""
Kubernetes Resource Usage Analyzer
Author: DevOps-CommandCenter
Description: Analyze Kubernetes resource usage patterns and provide optimization recommendations
"""

import kubernetes
import json
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ResourceUsage:
    namespace: str
    pod_name: str
    container_name: str
    cpu_requests: str
    cpu_limits: str
    memory_requests: str
    memory_limits: str
    actual_cpu_usage: float
    actual_memory_usage: float
    cpu_utilization: float
    memory_utilization: float
    recommendation: str

class K8sResourceAnalyzer:
    def __init__(self):
        kubernetes.config.load_kube_config()
        self.v1 = kubernetes.client.CoreV1Api()
        self.custom_api = kubernetes.client.CustomObjectsApi()
        self.metrics_api = kubernetes.client.CustomObjectsApi()
    
    def analyze_resource_usage(self, namespace: str = None) -> List[ResourceUsage]:
        """Analyze resource usage across pods"""
        usage_data = []
        
        # Get all pods
        pods = self.v1.list_pod_for_all_namespaces() if not namespace else self.v1.list_namespaced_pod(namespace)
        
        for pod in pods.items:
            if pod.status.phase == 'Running':
                try:
                    pod_usage = self._analyze_pod(pod)
                    usage_data.extend(pod_usage)
                except Exception as e:
                    logger.error(f"Error analyzing pod {pod.metadata.name}: {str(e)}")
        
        return usage_data
    
    def _analyze_pod(self, pod) -> List[ResourceUsage]:
        """Analyze a single pod's resource usage"""
        usage_list = []
        
        # Get metrics for the pod
        pod_metrics = self._get_pod_metrics(pod.metadata.namespace, pod.metadata.name)
        
        for container in pod.spec.containers:
            # Get container resource specs
            cpu_requests = container.resources.requests.get('cpu', '0') if container.resources.requests else '0'
            cpu_limits = container.resources.limits.get('cpu', '0') if container.resources.limits else '0'
            memory_requests = container.resources.requests.get('memory', '0') if container.resources.requests else '0'
            memory_limits = container.resources.limits.get('memory', '0') if container.resources.limits else '0'
            
            # Get actual usage from metrics
            container_metrics = pod_metrics.get(container.name, {})
            actual_cpu = container_metrics.get('cpu', 0)
            actual_memory = container_metrics.get('memory', 0)
            
            # Calculate utilization
            cpu_util = self._calculate_cpu_utilization(actual_cpu, cpu_requests)
            memory_util = self._calculate_memory_utilization(actual_memory, memory_requests)
            
            # Generate recommendation
            recommendation = self._generate_recommendation(
                cpu_util, memory_util, cpu_requests, memory_requests, 
                cpu_limits, memory_limits
            )
            
            usage = ResourceUsage(
                namespace=pod.metadata.namespace,
                pod_name=pod.metadata.name,
                container_name=container.name,
                cpu_requests=cpu_requests,
                cpu_limits=cpu_limits,
                memory_requests=memory_requests,
                memory_limits=memory_limits,
                actual_cpu_usage=actual_cpu,
                actual_memory_usage=actual_memory,
                cpu_utilization=cpu_util,
                memory_utilization=memory_util,
                recommendation=recommendation
            )
            
            usage_list.append(usage)
        
        return usage_list
    
    def _get_pod_metrics(self, namespace: str, pod_name: str) -> Dict[str, Dict]:
        """Get metrics for a pod"""
        try:
            # Get metrics from metrics API
            metrics = self.metrics_api.list_namespaced_custom_object(
                group="metrics.k8s.io",
                version="v1beta1",
                namespace=namespace,
                plural="pods"
            )
            
            for item in metrics['items']:
                if item['metadata']['name'] == pod_name:
                    container_metrics = {}
                    for container in item['containers']:
                        container_metrics[container['name']] = {
                            'cpu': self._parse_cpu(container['usage']['cpu']),
                            'memory': self._parse_memory(container['usage']['memory'])
                        }
                    return container_metrics
        
        except Exception as e:
            logger.warning(f"Could not get metrics for pod {pod_name}: {str(e)}")
        
        return {}
    
    def _parse_cpu(self, cpu_str: str) -> float:
        """Parse CPU usage string to cores"""
        if cpu_str.endswith('n'):
            return int(cpu_str[:-1]) / 1_000_000_000  # nanocores to cores
        elif cpu_str.endswith('m'):
            return int(cpu_str[:-1]) / 1000  # millicores to cores
        else:
            return float(cpu_str)
    
    def _parse_memory(self, memory_str: str) -> float:
        """Parse memory usage string to MB"""
        if memory_str.endswith('Ki'):
            return int(memory_str[:-2]) / 1024  # KiB to MB
        elif memory_str.endswith('Mi'):
            return int(memory_str[:-2])  # MiB to MB
        elif memory_str.endswith('Gi'):
            return int(memory_str[:-2]) * 1024  # GiB to MB
        else:
            return int(memory_str) / (1024 * 1024)  # Bytes to MB
    
    def _calculate_cpu_utilization(self, actual: float, requested: str) -> float:
        """Calculate CPU utilization percentage"""
        if not requested or requested == '0':
            return 0
        
        requested_cores = self._parse_cpu(requested)
        return (actual / requested_cores * 100) if requested_cores > 0 else 0
    
    def _calculate_memory_utilization(self, actual: float, requested: str) -> float:
        """Calculate memory utilization percentage"""
        if not requested or requested == '0':
            return 0
        
        requested_mb = self._parse_memory(requested)
        return (actual / requested_mb * 100) if requested_mb > 0 else 0
    
    def _generate_recommendation(self, cpu_util: float, memory_util: float,
                               cpu_req: str, memory_req: str,
                               cpu_limit: str, memory_limit: str) -> str:
        """Generate optimization recommendation"""
        recommendations = []
        
        # CPU recommendations
        if cpu_util < 20:
            recommendations.append("Consider reducing CPU requests (underutilized)")
        elif cpu_util > 90:
            recommendations.append("Consider increasing CPU requests (overutilized)")
        
        if cpu_req == '0':
            recommendations.append("Set CPU requests for better scheduling")
        
        if cpu_limit == '0' and cpu_req != '0':
            recommendations.append("Set CPU limits to prevent resource contention")
        
        # Memory recommendations
        if memory_util < 20:
            recommendations.append("Consider reducing memory requests (underutilized)")
        elif memory_util > 90:
            recommendations.append("Consider increasing memory requests (overutilized)")
        
        if memory_req == '0':
            recommendations.append("Set memory requests for better scheduling")
        
        if memory_limit == '0' and memory_req != '0':
            recommendations.append("Set memory limits to prevent resource contention")
        
        # Limit vs request ratio
        if cpu_req != '0' and cpu_limit != '0':
            req_cores = self._parse_cpu(cpu_req)
            limit_cores = self._parse_cpu(cpu_limit)
            if limit_cores / req_cores > 3:
                recommendations.append("Consider reducing CPU limit ratio (currently >3x)")
        
        return "; ".join(recommendations) if recommendations else "Resource allocation appears optimal"
    
    def generate_report(self, usage_data: List[ResourceUsage]) -> Dict[str, Any]:
        """Generate resource usage analysis report"""
        # Calculate statistics
        total_containers = len(usage_data)
        underutilized_cpu = len([u for u in usage_data if u.cpu_utilization < 20])
        overutilized_cpu = len([u for u in usage_data if u.cpu_utilization > 80])
        underutilized_memory = len([u for u in usage_data if u.memory_utilization < 20])
        overutilized_memory = len([u for u in usage_data if u.memory_utilization > 80])
        
        # Group by namespace
        namespace_stats = defaultdict(list)
        for usage in usage_data:
            namespace_stats[usage.namespace].append(usage)
        
        # Find top resource consumers
        top_cpu_users = sorted(usage_data, key=lambda x: x.actual_cpu_usage, reverse=True)[:5]
        top_memory_users = sorted(usage_data, key=lambda x: x.actual_memory_usage, reverse=True)[:5]
        
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_containers_analyzed": total_containers,
                "cpu_underutilized": underutilized_cpu,
                "cpu_overutilized": overutilized_cpu,
                "memory_underutilized": underutilized_memory,
                "memory_overutilized": overutilized_memory,
                "optimization_opportunities": underutilized_cpu + overutilized_cpu + underutilized_memory + overutilized_memory
            },
            "namespace_breakdown": {
                ns: {
                    "container_count": len(containers),
                    "avg_cpu_util": sum(c.cpu_utilization for c in containers) / len(containers),
                    "avg_memory_util": sum(c.memory_utilization for c in containers) / len(containers)
                }
                for ns, containers in namespace_stats.items()
            },
            "top_cpu_consumers": [asdict(u) for u in top_cpu_users],
            "top_memory_consumers": [asdict(u) for u in top_memory_users],
            "detailed_usage": [asdict(u) for u in usage_data],
            "recommendations": self._generate_cluster_recommendations(usage_data)
        }
    
    def _generate_cluster_recommendations(self, usage_data: List[ResourceUsage]) -> List[str]:
        """Generate cluster-level recommendations"""
        recommendations = []
        
        # Analyze patterns
        cpu_utils = [u.cpu_utilization for u in usage_data if u.cpu_utilization > 0]
        memory_utils = [u.memory_utilization for u in usage_data if u.memory_utilization > 0]
        
        if cpu_utils:
            avg_cpu = sum(cpu_utils) / len(cpu_utils)
            if avg_cpu < 30:
                recommendations.append("Cluster CPU resources appear overprovisioned - consider right-sizing")
            elif avg_cpu > 70:
                recommendations.append("Cluster CPU resources are heavily utilized - consider scaling")
        
        if memory_utils:
            avg_memory = sum(memory_utils) / len(memory_utils)
            if avg_memory < 30:
                recommendations.append("Cluster memory resources appear overprovisioned - consider right-sizing")
            elif avg_memory > 70:
                recommendations.append("Cluster memory resources are heavily utilized - consider scaling")
        
        # Check for missing requests/limits
        no_requests = len([u for u in usage_data if u.cpu_requests == '0' or u.memory_requests == '0'])
        no_limits = len([u for u in usage_data if u.cpu_limits == '0' or u.memory_limits == '0'])
        
        if no_requests > 0:
            recommendations.append(f"{no_requests} containers lack resource requests - set requests for better scheduling")
        
        if no_limits > 0:
            recommendations.append(f"{no_limits} containers lack resource limits - set limits to prevent resource contention")
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='Analyze Kubernetes resource usage')
    parser.add_argument('--namespace', help='Specific namespace to analyze')
    parser.add_argument('--output', default='k8s_resource_usage_report.json')
    parser.add_argument('--top', type=int, default=10, help='Number of top resources to show')
    
    args = parser.parse_args()
    
    try:
        analyzer = K8sResourceAnalyzer()
        usage_data = analyzer.analyze_resource_usage(args.namespace)
        report = analyzer.generate_report(usage_data)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Kubernetes Resource Usage Analysis:")
        print(f"Total containers analyzed: {report['summary']['total_containers_analyzed']}")
        print(f"CPU underutilized: {report['summary']['cpu_underutilized']}")
        print(f"CPU overutilized: {report['summary']['cpu_overutilized']}")
        print(f"Memory underutilized: {report['summary']['memory_underutilized']}")
        print(f"Memory overutilized: {report['summary']['memory_overutilized']}")
        print(f"Optimization opportunities: {report['summary']['optimization_opportunities']}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error during resource analysis: {str(e)}")

if __name__ == "__main__":
    main()
