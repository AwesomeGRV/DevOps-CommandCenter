#!/usr/bin/env python3
"""
Metrics Collector
Author: DevOps-CommandCenter
Description: Collect and aggregate metrics from various sources for monitoring
"""

import json
import logging
import argparse
import time
import requests
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import threading
import queue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class MetricData:
    name: str
    value: float
    timestamp: datetime
    labels: Dict[str, str]
    source: str
    unit: str

class MetricsCollector:
    def __init__(self, config_file: str = "config/metrics_config.json"):
        self.config = self._load_config(config_file)
        self.metrics_queue = queue.Queue()
        self.collected_metrics = []
        self.is_running = False
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load metrics configuration"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default metrics configuration"""
        return {
            "collection_interval": 60,  # seconds
            "sources": {
                "system": {
                    "enabled": True,
                    "metrics": ["cpu", "memory", "disk", "network"]
                },
                "application": {
                    "enabled": True,
                    "endpoints": [
                        {"name": "api_metrics", "url": "http://localhost:8000/metrics"},
                        {"name": "app_metrics", "url": "http://localhost:3000/metrics"}
                    ]
                },
                "prometheus": {
                    "enabled": True,
                    "url": "http://localhost:9090/api/v1/query",
                    "queries": [
                        {"name": "http_requests_total", "query": "rate(http_requests_total[5m])"},
                        {"name": "response_time", "query": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))"}
                    ]
                },
                "cloudwatch": {
                    "enabled": False,
                    "metrics": [
                        {"namespace": "AWS/EC2", "metric": "CPUUtilization", "dimensions": []}
                    ]
                }
            },
            "storage": {
                "type": "file",
                "path": "metrics_data.json"
            }
        }
    
    def start_collection(self, duration_minutes: int = 60):
        """Start metrics collection"""
        self.is_running = True
        logger.info(f"Starting metrics collection for {duration_minutes} minutes")
        
        # Start collection threads
        threads = []
        
        if self.config["sources"]["system"]["enabled"]:
            system_thread = threading.Thread(target=self._collect_system_metrics_loop)
            system_thread.daemon = True
            system_thread.start()
            threads.append(system_thread)
        
        if self.config["sources"]["application"]["enabled"]:
            app_thread = threading.Thread(target=self._collect_application_metrics_loop)
            app_thread.daemon = True
            app_thread.start()
            threads.append(app_thread)
        
        if self.config["sources"]["prometheus"]["enabled"]:
            prometheus_thread = threading.Thread(target=self._collect_prometheus_metrics_loop)
            prometheus_thread.daemon = True
            prometheus_thread.start()
            threads.append(prometheus_thread)
        
        # Run for specified duration
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        
        while datetime.now() < end_time and self.is_running:
            time.sleep(1)
        
        self.is_running = False
        logger.info("Metrics collection completed")
        
        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=5)
        
        # Process collected metrics
        self._process_metrics()
    
    def _collect_system_metrics_loop(self):
        """Collect system metrics in a loop"""
        while self.is_running:
            try:
                metrics = self._collect_system_metrics()
                for metric in metrics:
                    self.metrics_queue.put(metric)
            except Exception as e:
                logger.error(f"Error collecting system metrics: {str(e)}")
            
            time.sleep(self.config["collection_interval"])
    
    def _collect_system_metrics(self) -> List[MetricData]:
        """Collect system metrics"""
        metrics = []
        timestamp = datetime.now()
        
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        metrics.append(MetricData(
            name="system_cpu_usage",
            value=cpu_percent,
            timestamp=timestamp,
            labels={"host": "localhost"},
            source="system",
            unit="percent"
        ))
        
        # Memory metrics
        memory = psutil.virtual_memory()
        metrics.append(MetricData(
            name="system_memory_usage",
            value=memory.percent,
            timestamp=timestamp,
            labels={"host": "localhost"},
            source="system",
            unit="percent"
        ))
        
        metrics.append(MetricData(
            name="system_memory_available",
            value=memory.available / (1024**3),  # GB
            timestamp=timestamp,
            labels={"host": "localhost"},
            source="system",
            unit="gigabytes"
        ))
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        metrics.append(MetricData(
            name="system_disk_usage",
            value=disk.percent,
            timestamp=timestamp,
            labels={"host": "localhost", "mountpoint": "/"},
            source="system",
            unit="percent"
        ))
        
        # Network metrics
        network = psutil.net_io_counters()
        metrics.append(MetricData(
            name="system_network_bytes_sent",
            value=network.bytes_sent,
            timestamp=timestamp,
            labels={"host": "localhost"},
            source="system",
            unit="bytes"
        ))
        
        metrics.append(MetricData(
            name="system_network_bytes_recv",
            value=network.bytes_recv,
            timestamp=timestamp,
            labels={"host": "localhost"},
            source="system",
            unit="bytes"
        ))
        
        return metrics
    
    def _collect_application_metrics_loop(self):
        """Collect application metrics in a loop"""
        while self.is_running:
            try:
                metrics = self._collect_application_metrics()
                for metric in metrics:
                    self.metrics_queue.put(metric)
            except Exception as e:
                logger.error(f"Error collecting application metrics: {str(e)}")
            
            time.sleep(self.config["collection_interval"])
    
    def _collect_application_metrics(self) -> List[MetricData]:
        """Collect application metrics"""
        metrics = []
        timestamp = datetime.now()
        
        for endpoint in self.config["sources"]["application"]["endpoints"]:
            try:
                response = requests.get(endpoint["url"], timeout=10)
                
                if response.status_code == 200:
                    # Parse Prometheus format metrics
                    parsed_metrics = self._parse_prometheus_format(response.text, endpoint["name"])
                    metrics.extend(parsed_metrics)
                else:
                    logger.warning(f"Failed to get metrics from {endpoint['url']}: {response.status_code}")
            
            except Exception as e:
                logger.warning(f"Error collecting metrics from {endpoint['url']}: {str(e)}")
        
        return metrics
    
    def _parse_prometheus_format(self, metrics_text: str, source: str) -> List[MetricData]:
        """Parse Prometheus format metrics"""
        metrics = []
        lines = metrics_text.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse metric line
            if '{' in line:
                # Metric with labels
                metric_part, value_part = line.split(' ', 1)
                name_part, labels_part = metric_part.split('{', 1)
                labels_str = labels_part.rstrip('}')
                
                # Parse labels
                labels = {}
                if labels_str:
                    for label_pair in labels_str.split(','):
                        if '=' in label_pair:
                            key, value = label_pair.split('=', 1)
                            labels[key.strip()] = value.strip('"')
                
                value = float(value_part)
            else:
                # Simple metric without labels
                name_part, value_part = line.split(' ', 1)
                labels = {}
                value = float(value_part)
            
            metrics.append(MetricData(
                name=name_part,
                value=value,
                timestamp=datetime.now(),
                labels=labels,
                source=source,
                unit=""
            ))
        
        return metrics
    
    def _collect_prometheus_metrics_loop(self):
        """Collect Prometheus metrics in a loop"""
        while self.is_running:
            try:
                metrics = self._collect_prometheus_metrics()
                for metric in metrics:
                    self.metrics_queue.put(metric)
            except Exception as e:
                logger.error(f"Error collecting Prometheus metrics: {str(e)}")
            
            time.sleep(self.config["collection_interval"])
    
    def _collect_prometheus_metrics(self) -> List[MetricData]:
        """Collect metrics from Prometheus"""
        metrics = []
        timestamp = datetime.now()
        
        for query_config in self.config["sources"]["prometheus"]["queries"]:
            try:
                params = {'query': query_config["query"]}
                response = requests.get(
                    self.config["sources"]["prometheus"]["url"],
                    params=params,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data['status'] == 'success' and data['data']['result']:
                        for result in data['data']['result']:
                            metric_name = query_config["name"]
                            value = float(result['value'][1])
                            labels = result['metric']
                            
                            metrics.append(MetricData(
                                name=metric_name,
                                value=value,
                                timestamp=timestamp,
                                labels=labels,
                                source="prometheus",
                                unit=""
                            ))
            
            except Exception as e:
                logger.warning(f"Error executing Prometheus query {query_config['query']}: {str(e)}")
        
        return metrics
    
    def _process_metrics(self):
        """Process collected metrics"""
        logger.info("Processing collected metrics...")
        
        # Get all metrics from queue
        while not self.metrics_queue.empty():
            try:
                metric = self.metrics_queue.get_nowait()
                self.collected_metrics.append(metric)
            except queue.Empty:
                break
        
        logger.info(f"Processed {len(self.collected_metrics)} metrics")
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate metrics collection report"""
        if not self.collected_metrics:
            return {"error": "No metrics collected"}
        
        # Group metrics by name
        metrics_by_name = {}
        for metric in self.collected_metrics:
            if metric.name not in metrics_by_name:
                metrics_by_name[metric.name] = []
            metrics_by_name[metric.name].append(metric)
        
        # Calculate statistics for each metric
        metric_stats = {}
        for name, metrics in metrics_by_name.items():
            values = [m.value for m in metrics]
            
            metric_stats[name] = {
                "count": len(values),
                "min": min(values),
                "max": max(values),
                "avg": sum(values) / len(values),
                "latest": values[-1] if values else 0,
                "source": metrics[0].source,
                "unit": metrics[0].unit
            }
        
        # Time range
        timestamps = [m.timestamp for m in self.collected_metrics]
        time_range = {
            "start": min(timestamps).isoformat(),
            "end": max(timestamps).isoformat(),
            "duration_minutes": (max(timestamps) - min(timestamps)).total_seconds() / 60
        }
        
        # Source breakdown
        source_counts = {}
        for metric in self.collected_metrics:
            source_counts[metric.source] = source_counts.get(metric.source, 0) + 1
        
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_metrics": len(self.collected_metrics),
                "unique_metric_names": len(metrics_by_name),
                "time_range": time_range,
                "source_breakdown": source_counts
            },
            "metric_statistics": metric_stats,
            "raw_metrics": [asdict(m) for m in self.collected_metrics[-100:]]  # Last 100 metrics
        }
    
    def save_metrics(self, filename: str = None):
        """Save metrics to file"""
        if not filename:
            filename = self.config["storage"]["path"]
        
        try:
            with open(filename, 'w') as f:
                json.dump([asdict(m) for m in self.collected_metrics], f, indent=2, default=str)
            logger.info(f"Metrics saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving metrics: {str(e)}")
    
    def export_to_prometheus_format(self, filename: str = "metrics.prom"):
        """Export metrics in Prometheus format"""
        try:
            with open(filename, 'w') as f:
                # Group metrics by name and labels
                metric_groups = {}
                
                for metric in self.collected_metrics:
                    key = (metric.name, tuple(sorted(metric.labels.items())))
                    if key not in metric_groups:
                        metric_groups[key] = []
                    metric_groups[key].append(metric)
                
                # Write latest value for each metric group
                for (name, labels), metrics in metric_groups.items():
                    latest_metric = max(metrics, key=lambda m: m.timestamp)
                    
                    # Write metric name and labels
                    if labels:
                        label_str = ','.join([f'{k}="{v}"' for k, v in labels])
                        f.write(f"{name}{{{label_str}}} {latest_metric.value}\n")
                    else:
                        f.write(f"{name} {latest_metric.value}\n")
            
            logger.info(f"Metrics exported to Prometheus format: {filename}")
        
        except Exception as e:
            logger.error(f"Error exporting metrics: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Collect metrics from various sources')
    parser.add_argument('--duration', type=int, default=60, help='Collection duration in minutes')
    parser.add_argument('--config', default='config/metrics_config.json')
    parser.add_argument('--output', default='metrics_report.json')
    parser.add_argument('--export-prometheus', default='metrics.prom')
    
    args = parser.parse_args()
    
    try:
        collector = MetricsCollector(args.config)
        
        # Start collection
        collector.start_collection(args.duration)
        
        # Generate report
        report = collector.generate_report()
        
        # Save results
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        collector.save_metrics()
        collector.export_to_prometheus_format(args.export_prometheus)
        
        print(f"Metrics Collection Summary:")
        print(f"Total metrics collected: {report['summary']['total_metrics']}")
        print(f"Unique metric names: {report['summary']['unique_metric_names']}")
        print(f"Collection duration: {report['summary']['time_range']['duration_minutes']:.1f} minutes")
        print(f"Sources: {list(report['summary']['source_breakdown'].keys())}")
        print(f"Report saved to {args.output}")
        print(f"Raw metrics saved to metrics_data.json")
        print(f"Prometheus export saved to {args.export_prometheus}")
        
    except Exception as e:
        logger.error(f"Error during metrics collection: {str(e)}")

if __name__ == "__main__":
    main()
