#!/usr/bin/env python3
"""
API Latency Checker
Author: CloudOps-SRE-Toolkit
Description: Monitor and analyze API endpoint latency and performance
"""

import os
import json
import logging
import argparse
import time
import asyncio
import aiohttp
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'api_latency_check_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class APIMetric:
    """Data class for API performance metrics"""
    url: str
    method: str
    status_code: int
    response_time_ms: float
    timestamp: datetime
    success: bool
    error_message: Optional[str] = None
    response_size_bytes: Optional[int] = None
    dns_time_ms: Optional[float] = None
    connect_time_ms: Optional[float] = None
    ssl_time_ms: Optional[float] = None

@dataclass
class APIEndpoint:
    """Data class for API endpoint configuration"""
    name: str
    url: str
    method: str = "GET"
    headers: Dict[str, str] = None
    body: Optional[str] = None
    timeout: int = 30
    expected_status_codes: List[int] = None
    auth: Optional[Dict[str, str]] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.expected_status_codes is None:
            self.expected_status_codes = [200, 201, 202, 204]

@dataclass
class LatencyReport:
    """Data class for latency analysis report"""
    timestamp: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    average_latency_ms: float
    median_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    endpoints_summary: Dict[str, Any]
    time_series_data: List[Dict[str, Any]]
    recommendations: List[str]

class APILatencyChecker:
    """Monitor API endpoint latency and performance"""
    
    def __init__(self, config_file: str = "config/api_config.json"):
        self.config = self._load_config(config_file)
        self.endpoints = self._load_endpoints()
        self.metrics_history = []
        self.session = None
        
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
            "endpoints": [
                {
                    "name": "Google Homepage",
                    "url": "https://www.google.com",
                    "method": "GET",
                    "timeout": 10
                },
                {
                    "name": "JSONPlaceholder Test",
                    "url": "https://jsonplaceholder.typicode.com/posts/1",
                    "method": "GET",
                    "timeout": 10
                }
            ],
            "monitoring": {
                "interval_seconds": 60,
                "duration_minutes": 10,
                "concurrent_requests": 5,
                "retry_attempts": 3,
                "retry_delay_seconds": 1
            },
            "thresholds": {
                "warning_latency_ms": 1000,
                "critical_latency_ms": 5000,
                "error_rate_threshold": 0.05  # 5%
            },
            "output": {
                "format": ["json", "csv", "dashboard"],
                "chart_days": 7
            },
            "alerts": {
                "webhook_url": os.getenv("ALERT_WEBHOOK_URL", ""),
                "slack_webhook": os.getenv("SLACK_WEBHOOK_URL", "")
            }
        }
    
    def _load_endpoints(self) -> List[APIEndpoint]:
        """Load API endpoints from configuration"""
        endpoints = []
        
        for endpoint_config in self.config.get("endpoints", []):
            endpoint = APIEndpoint(
                name=endpoint_config["name"],
                url=endpoint_config["url"],
                method=endpoint_config.get("method", "GET"),
                headers=endpoint_config.get("headers", {}),
                body=endpoint_config.get("body"),
                timeout=endpoint_config.get("timeout", 30),
                expected_status_codes=endpoint_config.get("expected_status_codes", [200, 201, 202, 204]),
                auth=endpoint_config.get("auth")
            )
            endpoints.append(endpoint)
        
        logger.info(f"Loaded {len(endpoints)} API endpoints for monitoring")
        return endpoints
    
    async def create_session(self):
        """Create aiohttp session with proper configuration"""
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector
        )
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
    
    async def check_endpoint(self, endpoint: APIEndpoint) -> APIMetric:
        """Check a single API endpoint"""
        start_time = time.time()
        timestamp = datetime.now()
        
        try:
            # Prepare request
            headers = endpoint.headers.copy()
            if endpoint.auth:
                if endpoint.auth.get("type") == "bearer":
                    headers["Authorization"] = f"Bearer {endpoint.auth['token']}"
                elif endpoint.auth.get("type") == "basic":
                    import base64
                    credentials = f"{endpoint.auth['username']}:{endpoint.auth['password']}"
                    encoded = base64.b64encode(credentials.encode()).decode()
                    headers["Authorization"] = f"Basic {encoded}"
            
            # Make request
            async with self.session.request(
                method=endpoint.method,
                url=endpoint.url,
                headers=headers,
                data=endpoint.body,
                timeout=endpoint.timeout
            ) as response:
                content = await response.read()
                response_time_ms = (time.time() - start_time) * 1000
                
                # Get timing information if available
                dns_time_ms = None
                connect_time_ms = None
                ssl_time_ms = None
                
                # Check if response is successful
                success = response.status in endpoint.expected_status_codes
                
                return APIMetric(
                    url=endpoint.url,
                    method=endpoint.method,
                    status_code=response.status,
                    response_time_ms=response_time_ms,
                    timestamp=timestamp,
                    success=success,
                    response_size_bytes=len(content) if content else 0,
                    dns_time_ms=dns_time_ms,
                    connect_time_ms=connect_time_ms,
                    ssl_time_ms=ssl_time_ms
                )
        
        except asyncio.TimeoutError:
            response_time_ms = (time.time() - start_time) * 1000
            return APIMetric(
                url=endpoint.url,
                method=endpoint.method,
                status_code=0,
                response_time_ms=response_time_ms,
                timestamp=timestamp,
                success=False,
                error_message="Request timeout"
            )
        
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            return APIMetric(
                url=endpoint.url,
                method=endpoint.method,
                status_code=0,
                response_time_ms=response_time_ms,
                timestamp=timestamp,
                success=False,
                error_message=str(e)
            )
    
    async def check_all_endpoints(self) -> List[APIMetric]:
        """Check all configured endpoints"""
        if not self.session:
            await self.create_session()
        
        tasks = []
        for endpoint in self.endpoints:
            # Create multiple concurrent requests for each endpoint
            concurrent_count = self.config.get("monitoring", {}).get("concurrent_requests", 1)
            for _ in range(concurrent_count):
                tasks.append(self.check_endpoint(endpoint))
        
        metrics = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and log them
        valid_metrics = []
        for metric in metrics:
            if isinstance(metric, Exception):
                logger.error(f"Error checking endpoint: {str(metric)}")
            else:
                valid_metrics.append(metric)
        
        return valid_metrics
    
    def analyze_metrics(self, metrics: List[APIMetric]) -> Dict[str, Any]:
        """Analyze collected metrics"""
        if not metrics:
            return {}
        
        # Overall statistics
        response_times = [m.response_time_ms for m in metrics if m.success]
        failed_requests = [m for m in metrics if not m.success]
        
        analysis = {
            "total_requests": len(metrics),
            "successful_requests": len(response_times),
            "failed_requests": len(failed_requests),
            "success_rate": len(response_times) / len(metrics) if metrics else 0,
            "error_rate": len(failed_requests) / len(metrics) if metrics else 0
        }
        
        if response_times:
            analysis.update({
                "average_latency_ms": statistics.mean(response_times),
                "median_latency_ms": statistics.median(response_times),
                "min_latency_ms": min(response_times),
                "max_latency_ms": max(response_times),
                "p95_latency_ms": self._percentile(response_times, 95),
                "p99_latency_ms": self._percentile(response_times, 99),
                "std_deviation_ms": statistics.stdev(response_times) if len(response_times) > 1 else 0
            })
        
        # Analyze by endpoint
        endpoint_analysis = {}
        for endpoint in self.endpoints:
            endpoint_metrics = [m for m in metrics if m.url == endpoint.url]
            if endpoint_metrics:
                endpoint_times = [m.response_time_ms for m in endpoint_metrics if m.success]
                endpoint_failures = [m for m in endpoint_metrics if not m.success]
                
                endpoint_analysis[endpoint.name] = {
                    "total_requests": len(endpoint_metrics),
                    "successful_requests": len(endpoint_times),
                    "failed_requests": len(endpoint_failures),
                    "success_rate": len(endpoint_times) / len(endpoint_metrics) if endpoint_metrics else 0,
                    "average_latency_ms": statistics.mean(endpoint_times) if endpoint_times else 0,
                    "median_latency_ms": statistics.median(endpoint_times) if endpoint_times else 0,
                    "p95_latency_ms": self._percentile(endpoint_times, 95) if endpoint_times else 0,
                    "status": self._determine_status(endpoint_times, endpoint_failures)
                }
        
        analysis["endpoints"] = endpoint_analysis
        
        # Analyze by status code
        status_code_analysis = defaultdict(int)
        for metric in metrics:
            status_code_analysis[metric.status_code] += 1
        
        analysis["status_codes"] = dict(status_code_analysis)
        
        return analysis
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile of data"""
        if not data:
            return 0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]
    
    def _determine_status(self, response_times: List[float], failures: List[APIMetric]) -> str:
        """Determine endpoint status based on metrics"""
        if not response_times and not failures:
            return "unknown"
        
        # Check error rate
        total_requests = len(response_times) + len(failures)
        error_rate = len(failures) / total_requests if total_requests > 0 else 0
        
        error_threshold = self.config.get("thresholds", {}).get("error_rate_threshold", 0.05)
        if error_rate > error_threshold:
            return "critical"
        
        # Check latency
        if response_times:
            avg_latency = statistics.mean(response_times)
            warning_threshold = self.config.get("thresholds", {}).get("warning_latency_ms", 1000)
            critical_threshold = self.config.get("thresholds", {}).get("critical_latency_ms", 5000)
            
            if avg_latency > critical_threshold:
                return "critical"
            elif avg_latency > warning_threshold:
                return "warning"
        
        return "healthy"
    
    def generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate performance recommendations"""
        recommendations = []
        
        if not analysis:
            return ["No data available for analysis"]
        
        # Error rate recommendations
        error_rate = analysis.get("error_rate", 0)
        if error_rate > 0.05:  # 5%
            recommendations.append(f"High error rate detected ({error_rate:.1%}). Check endpoint availability and error handling.")
        
        # Latency recommendations
        avg_latency = analysis.get("average_latency_ms", 0)
        if avg_latency > 5000:  # 5 seconds
            recommendations.append(f"High average latency ({avg_latency:.0f}ms). Consider optimizing API performance.")
        elif avg_latency > 1000:  # 1 second
            recommendations.append(f"Moderate latency ({avg_latency:.0f}ms). Monitor for performance degradation.")
        
        # Endpoint-specific recommendations
        endpoints = analysis.get("endpoints", {})
        for endpoint_name, endpoint_data in endpoints.items():
            status = endpoint_data.get("status", "unknown")
            if status == "critical":
                recommendations.append(f"Critical issues detected for {endpoint_name}. Immediate attention required.")
            elif status == "warning":
                recommendations.append(f"Performance warnings for {endpoint_name}. Monitor closely.")
        
        # General recommendations
        if analysis.get("success_rate", 0) < 0.95:
            recommendations.append("Consider implementing retry logic and circuit breakers.")
        
        recommendations.append("Set up automated monitoring and alerting for API performance.")
        recommendations.append("Implement performance testing in CI/CD pipeline.")
        
        return recommendations
    
    async def run_continuous_monitoring(self, duration_minutes: int = None):
        """Run continuous monitoring for specified duration"""
        if duration_minutes is None:
            duration_minutes = self.config.get("monitoring", {}).get("duration_minutes", 10)
        
        interval_seconds = self.config.get("monitoring", {}).get("interval_seconds", 60)
        
        logger.info(f"Starting continuous monitoring for {duration_minutes} minutes")
        logger.info(f"Checking endpoints every {interval_seconds} seconds")
        
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        
        while datetime.now() < end_time:
            try:
                logger.info("Running endpoint checks...")
                metrics = await self.check_all_endpoints()
                analysis = self.analyze_metrics(metrics)
                
                # Store metrics for historical analysis
                self.metrics_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "metrics": [asdict(m) for m in metrics],
                    "analysis": analysis
                })
                
                # Check for alerts
                await self.check_alerts(analysis)
                
                # Generate and save report
                await self.generate_and_save_report(analysis)
                
                logger.info(f"Completed check cycle. Success rate: {analysis.get('success_rate', 0):.1%}")
                
                # Wait for next interval
                if datetime.now() < end_time:
                    await asyncio.sleep(interval_seconds)
                
            except Exception as e:
                logger.error(f"Error during monitoring cycle: {str(e)}")
                await asyncio.sleep(10)  # Wait before retrying
        
        logger.info("Continuous monitoring completed")
    
    async def check_alerts(self, analysis: Dict[str, Any]):
        """Check if alerts should be triggered"""
        if not analysis:
            return
        
        # Check for critical issues
        critical_endpoints = [
            name for name, data in analysis.get("endpoints", {}).items()
            if data.get("status") == "critical"
        ]
        
        if critical_endpoints:
            alert_message = f"🚨 CRITICAL: Performance issues detected for endpoints: {', '.join(critical_endpoints)}"
            await self.send_alert(alert_message, "critical")
        
        # Check for high error rate
        error_rate = analysis.get("error_rate", 0)
        error_threshold = self.config.get("thresholds", {}).get("error_rate_threshold", 0.05)
        if error_rate > error_threshold:
            alert_message = f"⚠️ WARNING: High error rate detected: {error_rate:.1%}"
            await self.send_alert(alert_message, "warning")
    
    async def send_alert(self, message: str, severity: str):
        """Send alert to configured channels"""
        # Send webhook alert
        webhook_url = self.config.get("alerts", {}).get("webhook_url")
        if webhook_url:
            await self._send_webhook_alert(webhook_url, message, severity)
        
        # Send Slack alert
        slack_webhook = self.config.get("alerts", {}).get("slack_webhook")
        if slack_webhook:
            await self._send_slack_alert(slack_webhook, message, severity)
    
    async def _send_webhook_alert(self, url: str, message: str, severity: str):
        """Send alert via webhook"""
        try:
            async with self.session.post(url, json={
                "timestamp": datetime.now().isoformat(),
                "severity": severity,
                "message": message,
                "source": "api-latency-checker"
            }) as response:
                if response.status == 200:
                    logger.info("Webhook alert sent successfully")
                else:
                    logger.error(f"Failed to send webhook alert: {response.status}")
        except Exception as e:
            logger.error(f"Error sending webhook alert: {str(e)}")
    
    async def _send_slack_alert(self, url: str, message: str, severity: str):
        """Send alert to Slack"""
        try:
            color = {
                "critical": "danger",
                "warning": "warning",
                "info": "good"
            }.get(severity, "warning")
            
            payload = {
                "attachments": [{
                    "color": color,
                    "title": "API Performance Alert",
                    "text": message,
                    "ts": int(time.time())
                }]
            }
            
            async with self.session.post(url, json=payload) as response:
                if response.status == 200:
                    logger.info("Slack alert sent successfully")
                else:
                    logger.error(f"Failed to send Slack alert: {response.status}")
        except Exception as e:
            logger.error(f"Error sending Slack alert: {str(e)}")
    
    async def generate_and_save_report(self, analysis: Dict[str, Any]):
        """Generate and save monitoring report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create report data
        report = LatencyReport(
            timestamp=datetime.now().isoformat(),
            total_requests=analysis.get("total_requests", 0),
            successful_requests=analysis.get("successful_requests", 0),
            failed_requests=analysis.get("failed_requests", 0),
            average_latency_ms=analysis.get("average_latency_ms", 0),
            median_latency_ms=analysis.get("median_latency_ms", 0),
            p95_latency_ms=analysis.get("p95_latency_ms", 0),
            p99_latency_ms=analysis.get("p99_latency_ms", 0),
            min_latency_ms=analysis.get("min_latency_ms", 0),
            max_latency_ms=analysis.get("max_latency_ms", 0),
            endpoints_summary=analysis.get("endpoints", {}),
            time_series_data=self.metrics_history[-10:],  # Last 10 data points
            recommendations=self.generate_recommendations(analysis)
        )
        
        # Save JSON report
        json_file = f"api_latency_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        
        logger.info(f"Report saved to: {json_file}")
        
        # Generate dashboard if configured
        if "dashboard" in self.config.get("output", {}).get("format", []):
            self.generate_dashboard()
    
    def generate_dashboard(self):
        """Generate performance dashboard"""
        if not self.metrics_history:
            logger.warning("No historical data available for dashboard")
            return
        
        # Prepare data for visualization
        timestamps = [datetime.fromisoformat(d["timestamp"]) for d in self.metrics_history]
        avg_latencies = [d["analysis"].get("average_latency_ms", 0) for d in self.metrics_history]
        success_rates = [d["analysis"].get("success_rate", 0) * 100 for d in self.metrics_history]
        
        # Create dashboard
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('API Performance Dashboard', fontsize=16)
        
        # 1. Average latency over time
        axes[0, 0].plot(timestamps, avg_latencies, marker='o', linewidth=2)
        axes[0, 0].set_title('Average Latency Over Time')
        axes[0, 0].set_ylabel('Latency (ms)')
        axes[0, 0].tick_params(axis='x', rotation=45)
        axes[0, 0].grid(True, alpha=0.3)
        
        # 2. Success rate over time
        axes[0, 1].plot(timestamps, success_rates, marker='o', color='green', linewidth=2)
        axes[0, 1].set_title('Success Rate Over Time')
        axes[0, 1].set_ylabel('Success Rate (%)')
        axes[0, 1].tick_params(axis='x', rotation=45)
        axes[0, 1].grid(True, alpha=0.3)
        
        # 3. Current endpoint performance
        if self.metrics_history:
            latest_data = self.metrics_history[-1]["analysis"].get("endpoints", {})
            endpoints = list(latest_data.keys())
            latencies = [latest_data[ep].get("average_latency_ms", 0) for ep in endpoints]
            
            axes[1, 0].bar(endpoints, latencies, color='skyblue')
            axes[1, 0].set_title('Current Endpoint Latency')
            axes[1, 0].set_ylabel('Latency (ms)')
            axes[1, 0].tick_params(axis='x', rotation=45)
        
        # 4. Status distribution
        if self.metrics_history:
            latest_data = self.metrics_history[-1]["analysis"].get("endpoints", {})
            statuses = [data.get("status", "unknown") for data in latest_data.values()]
            status_counts = pd.Series(statuses).value_counts()
            
            colors = {'healthy': 'green', 'warning': 'orange', 'critical': 'red', 'unknown': 'gray'}
            bar_colors = [colors.get(status, 'gray') for status in status_counts.index]
            
            axes[1, 1].pie(status_counts.values, labels=status_counts.index, colors=bar_colors, autopct='%1.1f%%')
            axes[1, 1].set_title('Endpoint Status Distribution')
        
        plt.tight_layout()
        dashboard_file = f"api_latency_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(dashboard_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Dashboard saved to: {dashboard_file}")

async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Check API endpoint latency')
    parser.add_argument('--config', type=str, default='config/api_config.json', help='Configuration file path')
    parser.add_argument('--mode', choices=['single', 'continuous'], default='single', help='Monitoring mode')
    parser.add_argument('--duration', type=int, help='Monitoring duration in minutes (continuous mode)')
    parser.add_argument('--output-format', nargs='+', default=['json'], 
                       choices=['json', 'csv', 'dashboard'], help='Output formats')
    
    args = parser.parse_args()
    
    try:
        checker = APILatencyChecker(args.config)
        
        if args.mode == 'single':
            logger.info("Running single API latency check...")
            await checker.create_session()
            
            metrics = await checker.check_all_endpoints()
            analysis = checker.analyze_metrics(metrics)
            
            # Print summary
            print(f"\n=== API Latency Check Summary ===")
            print(f"Total requests: {analysis.get('total_requests', 0)}")
            print(f"Successful requests: {analysis.get('successful_requests', 0)}")
            print(f"Failed requests: {analysis.get('failed_requests', 0)}")
            print(f"Success rate: {analysis.get('success_rate', 0):.1%}")
            if analysis.get('average_latency_ms'):
                print(f"Average latency: {analysis['average_latency_ms']:.0f}ms")
                print(f"P95 latency: {analysis['p95_latency_ms']:.0f}ms")
            
            await checker.generate_and_save_report(analysis)
            await checker.close_session()
            
        else:
            await checker.run_continuous_monitoring(args.duration)
            await checker.close_session()
        
        logger.info("API latency monitoring completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during API latency monitoring: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
