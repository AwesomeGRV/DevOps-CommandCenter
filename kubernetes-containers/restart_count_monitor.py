#!/usr/bin/env python3
"""
Kubernetes Restart Count Monitor
Author: CloudOps-SRE-Toolkit
Description: Monitor and analyze pod restart counts across clusters
"""

import os
import json
import logging
import argparse
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import kubernetes
from kubernetes import client, config
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'restart_count_monitor_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class RestartMetrics:
    """Data class for restart metrics"""
    pod_name: str
    namespace: str
    container_name: str
    restart_count: int
    last_restart_time: Optional[str]
    pod_age: str
    node_name: str
    labels: Dict[str, str]
    restart_rate: float  # restarts per hour
    status: str  # normal, warning, critical

@dataclass
class RestartAnalysis:
    """Data class for analysis results"""
    timestamp: str
    total_pods: int
    total_containers: int
    total_restarts: int
    high_restart_pods: List[RestartMetrics]
    critical_restart_pods: List[RestartMetrics]
    restart_by_namespace: Dict[str, int]
    restart_by_node: Dict[str, int]
    restart_trends: List[Dict[str, Any]]

class RestartCountMonitor:
    """Monitor Kubernetes pod restart counts"""
    
    def __init__(self, config_file: str = "config/k8s_config.json"):
        self.config = self._load_config(config_file)
        self.thresholds = self.config.get("thresholds", {
            "warning": 5,
            "critical": 20,
            "restart_rate_warning": 0.5,  # restarts per hour
            "restart_rate_critical": 2.0
        })
        self.historical_data = []
        self.setup_kubernetes_client()
        
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found. Using defaults.")
            return self._get_default_config()
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in config file {config_file}")
            raise
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "thresholds": {
                "warning": 5,
                "critical": 20,
                "restart_rate_warning": 0.5,
                "restart_rate_critical": 2.0
            },
            "namespaces": ["default", "kube-system", "production"],
            "exclude_namespaces": ["kube-public"],
            "monitoring": {
                "prometheus_gateway": os.getenv("PROMETHEUS_GATEWAY", ""),
                "alert_webhook": os.getenv("ALERT_WEBHOOK", "")
            },
            "output": {
                "format": ["json", "csv", "dashboard"],
                "chart_days": 7
            }
        }
    
    def setup_kubernetes_client(self):
        """Setup Kubernetes client"""
        try:
            # Try to load in-cluster config first
            config.load_incluster_config()
            logger.info("Loaded in-cluster Kubernetes config")
        except:
            try:
                # Fall back to kubeconfig
                config.load_kube_config()
                logger.info("Loaded kubeconfig")
            except Exception as e:
                logger.error(f"Failed to load Kubernetes config: {str(e)}")
                raise
        
        self.v1 = client.CoreV1Api()
    
    def get_all_pods(self, namespaces: List[str] = None) -> List[Any]:
        """Get all pods from specified namespaces"""
        if namespaces is None:
            namespaces = self.config.get("namespaces", ["default"])
        
        all_pods = []
        
        for namespace in namespaces:
            if namespace in self.config.get("exclude_namespaces", []):
                continue
                
            try:
                pods = self.v1.list_namespaced_pod(namespace, timeout_seconds=30)
                all_pods.extend(pods.items)
                logger.info(f"Retrieved {len(pods.items)} pods from namespace: {namespace}")
            except Exception as e:
                logger.error(f"Error getting pods from namespace {namespace}: {str(e)}")
        
        return all_pods
    
    def extract_restart_metrics(self, pod: Any) -> List[RestartMetrics]:
        """Extract restart metrics from a pod"""
        metrics = []
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        node_name = pod.spec.node_name or "unknown"
        labels = pod.metadata.labels or {}
        
        # Calculate pod age
        creation_time = pod.metadata.creation_timestamp
        if creation_time:
            now = datetime.now(creation_time.tzinfo)
            pod_age_seconds = (now - creation_time).total_seconds()
            pod_age_hours = pod_age_seconds / 3600
            pod_age_str = f"{int(pod_age_hours)}h" if pod_age_hours < 24 else f"{int(pod_age_hours/24)}d"
        else:
            pod_age_hours = 0
            pod_age_str = "unknown"
        
        for container_status in pod.status.container_statuses or []:
            container_name = container_status.name
            restart_count = container_status.restart_count or 0
            
            # Get last restart time
            last_restart_time = None
            if container_status.last_state and container_status.last_state.terminated:
                last_restart_time = container_status.last_state.terminated.finished_at.isoformat()
            
            # Calculate restart rate (restarts per hour)
            restart_rate = restart_count / pod_age_hours if pod_age_hours > 0 else 0
            
            # Determine status based on thresholds
            if (restart_count >= self.thresholds["critical"] or 
                restart_rate >= self.thresholds["restart_rate_critical"]):
                status = "critical"
            elif (restart_count >= self.thresholds["warning"] or 
                  restart_rate >= self.thresholds["restart_rate_warning"]):
                status = "warning"
            else:
                status = "normal"
            
            metric = RestartMetrics(
                pod_name=pod_name,
                namespace=namespace,
                container_name=container_name,
                restart_count=restart_count,
                last_restart_time=last_restart_time,
                pod_age=pod_age_str,
                node_name=node_name,
                labels=labels,
                restart_rate=round(restart_rate, 3),
                status=status
            )
            
            metrics.append(metric)
        
        return metrics
    
    def analyze_restarts(self, metrics: List[RestartMetrics]) -> RestartAnalysis:
        """Analyze restart metrics"""
        total_pods = len(set((m.pod_name, m.namespace) for m in metrics))
        total_containers = len(metrics)
        total_restarts = sum(m.restart_count for m in metrics)
        
        high_restart_pods = [m for m in metrics if m.status == "warning"]
        critical_restart_pods = [m for m in metrics if m.status == "critical"]
        
        # Group by namespace
        restart_by_namespace = defaultdict(int)
        for metric in metrics:
            restart_by_namespace[metric.namespace] += metric.restart_count
        
        # Group by node
        restart_by_node = defaultdict(int)
        for metric in metrics:
            restart_by_node[metric.node_name] += metric.restart_count
        
        # Calculate trends (simplified - would need historical data for real trends)
        restart_trends = []
        for namespace, count in restart_by_namespace.items():
            restart_trends.append({
                "namespace": namespace,
                "restart_count": count,
                "trend": "stable"  # Placeholder - would calculate from historical data
            })
        
        return RestartAnalysis(
            timestamp=datetime.now().isoformat(),
            total_pods=total_pods,
            total_containers=total_containers,
            total_restarts=total_restarts,
            high_restart_pods=high_restart_pods,
            critical_restart_pods=critical_restart_pods,
            restart_by_namespace=dict(restart_by_namespace),
            restart_by_node=dict(restart_by_node),
            restart_trends=restart_trends
        )
    
    def monitor_continuously(self, interval_minutes: int = 5, max_iterations: int = None):
        """Monitor restarts continuously"""
        logger.info(f"Starting continuous monitoring with {interval_minutes} minute intervals")
        
        iteration = 0
        while max_iterations is None or iteration < max_iterations:
            try:
                logger.info(f"Monitoring iteration {iteration + 1}")
                
                # Get current metrics
                pods = self.get_all_pods()
                all_metrics = []
                
                for pod in pods:
                    metrics = self.extract_restart_metrics(pod)
                    all_metrics.extend(metrics)
                
                # Analyze metrics
                analysis = self.analyze_restarts(all_metrics)
                
                # Store historical data
                self.historical_data.append(analysis)
                
                # Keep only last 7 days of data
                if len(self.historical_data) > 1008:  # 7 days * 24 hours * 6 (10-minute intervals)
                    self.historical_data = self.historical_data[-1008:]
                
                # Generate alerts if needed
                self.generate_alerts(analysis)
                
                # Push metrics to Prometheus if configured
                if self.config.get("monitoring", {}).get("prometheus_gateway"):
                    self.push_metrics_to_prometheus(analysis)
                
                # Generate report
                self.generate_report(analysis)
                
                iteration += 1
                
                if max_iterations is None or iteration < max_iterations:
                    logger.info(f"Waiting {interval_minutes} minutes for next iteration...")
                    time.sleep(interval_minutes * 60)
                
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error during monitoring: {str(e)}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def generate_alerts(self, analysis: RestartAnalysis):
        """Generate alerts for critical restart issues"""
        critical_pods = analysis.critical_restart_pods
        
        if critical_pods:
            alert_message = f"🚨 CRITICAL: {len(critical_pods)} containers with critical restart counts detected!\n\n"
            
            for pod in critical_pods[:5]:  # Limit to top 5 in alert
                alert_message += f"Pod: {pod.pod_name}/{pod.container_name}\n"
                alert_message += f"Namespace: {pod.namespace}\n"
                alert_message += f"Restarts: {pod.restart_count} (Rate: {pod.restart_rate}/hour)\n"
                alert_message += f"Node: {pod.node_name}\n\n"
            
            logger.error(alert_message)
            
            # Send webhook alert if configured
            webhook_url = self.config.get("monitoring", {}).get("alert_webhook")
            if webhook_url:
                self.send_webhook_alert(alert_message, "critical")
    
    def send_webhook_alert(self, message: str, severity: str):
        """Send alert via webhook"""
        import requests
        
        webhook_url = self.config.get("monitoring", {}).get("alert_webhook")
        if not webhook_url:
            return
        
        payload = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "message": message,
            "source": "restart-count-monitor"
        }
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            if response.status_code == 200:
                logger.info("Alert sent successfully via webhook")
            else:
                logger.error(f"Failed to send webhook alert: {response.status_code}")
        except Exception as e:
            logger.error(f"Error sending webhook alert: {str(e)}")
    
    def push_metrics_to_prometheus(self, analysis: RestartAnalysis):
        """Push metrics to Prometheus gateway"""
        try:
            registry = CollectorRegistry()
            
            # Create gauges
            restart_count_gauge = Gauge(
                'kubernetes_pod_restart_count',
                'Number of container restarts',
                ['pod', 'namespace', 'container', 'node'],
                registry=registry
            )
            
            restart_rate_gauge = Gauge(
                'kubernetes_pod_restart_rate',
                'Container restart rate per hour',
                ['pod', 'namespace', 'container', 'node'],
                registry=registry
            )
            
            total_restarts_gauge = Gauge(
                'kubernetes_total_restarts',
                'Total restarts across all containers',
                registry=registry
            )
            
            critical_pods_gauge = Gauge(
                'kubernetes_critical_restart_pods',
                'Number of containers with critical restart counts',
                registry=registry
            )
            
            # Set gauge values (this would need actual metrics data)
            total_restarts_gauge.set(analysis.total_restarts)
            critical_pods_gauge.set(len(analysis.critical_restart_pods))
            
            # Push to gateway
            gateway_url = self.config.get("monitoring", {}).get("prometheus_gateway")
            if gateway_url:
                push_to_gateway(gateway_url, job='restart_monitor', registry=registry)
                logger.info("Metrics pushed to Prometheus gateway")
                
        except Exception as e:
            logger.error(f"Error pushing metrics to Prometheus: {str(e)}")
    
    def generate_report(self, analysis: RestartAnalysis):
        """Generate monitoring report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON report
        report_data = {
            "timestamp": analysis.timestamp,
            "summary": {
                "total_pods": analysis.total_pods,
                "total_containers": analysis.total_containers,
                "total_restarts": analysis.total_restarts,
                "high_restart_containers": len(analysis.high_restart_pods),
                "critical_restart_containers": len(analysis.critical_restart_pods)
            },
            "by_namespace": analysis.restart_by_namespace,
            "by_node": analysis.restart_by_node,
            "critical_pods": [asdict(pod) for pod in analysis.critical_restart_pods],
            "high_restart_pods": [asdict(pod) for pod in analysis.high_restart_pods]
        }
        
        json_file = f"restart_monitor_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"Report saved to: {json_file}")
        
        # Generate dashboard if configured
        if "dashboard" in self.config.get("output", {}).get("format", []):
            self.generate_dashboard()
    
    def generate_dashboard(self):
        """Generate monitoring dashboard"""
        if not self.historical_data:
            logger.warning("No historical data available for dashboard generation")
            return
        
        # Prepare data for visualization
        timestamps = [datetime.fromisoformat(d.timestamp.replace('Z', '+00:00')) for d in self.historical_data]
        total_restarts = [d.total_restarts for d in self.historical_data]
        critical_counts = [len(d.critical_restart_pods) for d in self.historical_data]
        
        # Create dashboard
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('Kubernetes Restart Count Monitor Dashboard', fontsize=16)
        
        # 1. Total restarts over time
        axes[0, 0].plot(timestamps, total_restarts, marker='o', linewidth=2)
        axes[0, 0].set_title('Total Restarts Over Time')
        axes[0, 0].set_ylabel('Total Restarts')
        axes[0, 0].tick_params(axis='x', rotation=45)
        axes[0, 0].grid(True, alpha=0.3)
        
        # 2. Critical restart pods over time
        axes[0, 1].plot(timestamps, critical_counts, marker='o', color='red', linewidth=2)
        axes[0, 1].set_title('Critical Restart Pods Over Time')
        axes[0, 1].set_ylabel('Critical Pods Count')
        axes[0, 1].tick_params(axis='x', rotation=45)
        axes[0, 1].grid(True, alpha=0.3)
        
        # 3. Current restarts by namespace
        if self.historical_data:
            latest_data = self.historical_data[-1]
            namespaces = list(latest_data.restart_by_namespace.keys())
            restart_counts = list(latest_data.restart_by_namespace.values())
            
            axes[1, 0].bar(namespaces, restart_counts, color='skyblue')
            axes[1, 0].set_title('Restarts by Namespace (Latest)')
            axes[1, 0].set_ylabel('Restart Count')
            axes[1, 0].tick_params(axis='x', rotation=45)
        
        # 4. Current restarts by node
        if self.historical_data:
            latest_data = self.historical_data[-1]
            nodes = list(latest_data.restart_by_node.keys())[:10]  # Top 10 nodes
            node_restarts = [latest_data.restart_by_node[node] for node in nodes]
            
            axes[1, 1].barh(nodes, node_restarts, color='lightcoral')
            axes[1, 1].set_title('Restarts by Node (Top 10)')
            axes[1, 1].set_xlabel('Restart Count')
        
        plt.tight_layout()
        dashboard_file = f"restart_monitor_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(dashboard_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Dashboard saved to: {dashboard_file}")

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Monitor Kubernetes pod restart counts')
    parser.add_argument('--config', type=str, default='config/k8s_config.json', help='Configuration file path')
    parser.add_argument('--mode', choices=['single', 'continuous'], default='single', 
                       help='Monitoring mode')
    parser.add_argument('--interval', type=int, default=5, help='Monitoring interval in minutes (continuous mode)')
    parser.add_argument('--max-iterations', type=int, help='Maximum iterations for continuous mode')
    parser.add_argument('--namespaces', nargs='+', help='Specific namespaces to monitor')
    
    args = parser.parse_args()
    
    try:
        monitor = RestartCountMonitor(args.config)
        
        if args.mode == 'single':
            logger.info("Running single monitoring cycle...")
            pods = monitor.get_all_pods(args.namespaces)
            all_metrics = []
            
            for pod in pods:
                metrics = monitor.extract_restart_metrics(pod)
                all_metrics.extend(metrics)
            
            analysis = monitor.analyze_restarts(all_metrics)
            monitor.generate_report(analysis)
            
            # Print summary
            print(f"\n=== Restart Count Monitor Summary ===")
            print(f"Total pods: {analysis.total_pods}")
            print(f"Total containers: {analysis.total_containers}")
            print(f"Total restarts: {analysis.total_restarts}")
            print(f"High restart containers: {len(analysis.high_restart_pods)}")
            print(f"Critical restart containers: {len(analysis.critical_restart_pods)}")
            
        else:
            monitor.monitor_continuously(args.interval, args.max_iterations)
        
        logger.info("Restart count monitoring completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during restart count monitoring: {str(e)}")
        raise

if __name__ == "__main__":
    main()
