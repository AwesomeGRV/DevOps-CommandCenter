#!/usr/bin/env python3
"""
Synthetic Monitoring Script
Author: CloudOps-SRE-Toolkit
Description: Synthetic monitoring for critical user journeys and API endpoints
"""

import os
import json
import logging
import argparse
import asyncio
import aiohttp
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urljoin, urlparse
import statistics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'synthetic_monitoring_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class SyntheticCheck:
    """Data class for synthetic check configuration"""
    name: str
    type: str  # 'api', 'web', 'journey'
    target: str
    method: str = "GET"
    headers: Dict[str, str] = None
    body: Optional[str] = None
    timeout: int = 30
    expected_status_codes: List[int] = None
    expected_response_time_ms: int = 5000
    checks: List[Dict[str, Any]] = None  # For journey checks
    frequency_minutes: int = 5
    locations: List[str] = None
    alert_threshold: float = 0.1  # 10% failure rate
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.expected_status_codes is None:
            self.expected_status_codes = [200, 201, 202, 204]
        if self.checks is None:
            self.checks = []
        if self.locations is None:
            self.locations = ["us-east-1"]

@dataclass
class CheckResult:
    """Data class for check result"""
    check_name: str
    check_type: str
    target: str
    timestamp: datetime
    success: bool
    response_time_ms: float
    status_code: Optional[int]
    error_message: Optional[str]
    response_size_bytes: Optional[int]
    location: str
    step_results: List[Dict[str, Any]] = None  # For journey checks

@dataclass
class MonitoringReport:
    """Data class for monitoring report"""
    timestamp: str
    total_checks: int
    successful_checks: int
    failed_checks: int
    average_response_time_ms: float
    availability_percentage: float
    check_results: List[CheckResult]
    check_summaries: Dict[str, Any]
    alerts: List[Dict[str, Any]]
    recommendations: List[str]

class SyntheticMonitor:
    """Synthetic monitoring for applications and APIs"""
    
    def __init__(self, config_file: str = "config/synthetic_monitoring_config.json"):
        self.config = self._load_config(config_file)
        self.checks = self._load_checks()
        self.results_history = []
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
            "checks": [
                {
                    "name": "Homepage Check",
                    "type": "web",
                    "target": "https://www.google.com",
                    "method": "GET",
                    "timeout": 10,
                    "expected_status_codes": [200],
                    "expected_response_time_ms": 3000,
                    "frequency_minutes": 5
                },
                {
                    "name": "API Health Check",
                    "type": "api",
                    "target": "https://jsonplaceholder.typicode.com/posts/1",
                    "method": "GET",
                    "timeout": 10,
                    "expected_status_codes": [200],
                    "expected_response_time_ms": 2000,
                    "frequency_minutes": 5
                }
            ],
            "monitoring": {
                "concurrent_checks": True,
                "max_concurrent": 10,
                "retry_attempts": 2,
                "retry_delay_seconds": 1,
                "locations": ["us-east-1", "us-west-2", "eu-west-1"]
            },
            "alerts": {
                "webhook_url": os.getenv("ALERT_WEBHOOK_URL", ""),
                "slack_webhook": os.getenv("SLACK_WEBHOOK_URL", ""),
                "email_enabled": False,
                "email_recipients": []
            },
            "output": {
                "format": ["json", "csv", "dashboard"],
                "retention_days": 30
            }
        }
    
    def _load_checks(self) -> List[SyntheticCheck]:
        """Load synthetic checks from configuration"""
        checks = []
        
        for check_config in self.config.get("checks", []):
            check = SyntheticCheck(
                name=check_config["name"],
                type=check_config["type"],
                target=check_config["target"],
                method=check_config.get("method", "GET"),
                headers=check_config.get("headers", {}),
                body=check_config.get("body"),
                timeout=check_config.get("timeout", 30),
                expected_status_codes=check_config.get("expected_status_codes", [200, 201, 202, 204]),
                expected_response_time_ms=check_config.get("expected_response_time_ms", 5000),
                checks=check_config.get("checks", []),
                frequency_minutes=check_config.get("frequency_minutes", 5),
                locations=check_config.get("locations", ["us-east-1"]),
                alert_threshold=check_config.get("alert_threshold", 0.1)
            )
            checks.append(check)
        
        logger.info(f"Loaded {len(checks)} synthetic checks")
        return checks
    
    async def create_session(self):
        """Create aiohttp session"""
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
    
    async def run_api_check(self, check: SyntheticCheck, location: str) -> CheckResult:
        """Run API check"""
        start_time = time.time()
        timestamp = datetime.now()
        
        try:
            headers = check.headers.copy()
            headers['User-Agent'] = 'CloudOps-SRE-Toolkit/1.0'
            
            async with self.session.request(
                method=check.method,
                url=check.target,
                headers=headers,
                data=check.body,
                timeout=check.timeout
            ) as response:
                content = await response.read()
                response_time_ms = (time.time() - start_time) * 1000
                
                success = (response.status in check.expected_status_codes and 
                          response_time_ms <= check.expected_response_time_ms)
                
                return CheckResult(
                    check_name=check.name,
                    check_type=check.type,
                    target=check.target,
                    timestamp=timestamp,
                    success=success,
                    response_time_ms=response_time_ms,
                    status_code=response.status,
                    error_message=None if success else f"Status: {response.status}, Time: {response_time_ms:.0f}ms",
                    response_size_bytes=len(content) if content else 0,
                    location=location
                )
        
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            return CheckResult(
                check_name=check.name,
                check_type=check.type,
                target=check.target,
                timestamp=timestamp,
                success=False,
                response_time_ms=response_time_ms,
                status_code=None,
                error_message=str(e),
                response_size_bytes=None,
                location=location
            )
    
    async def run_web_check(self, check: SyntheticCheck, location: str) -> CheckResult:
        """Run web check (similar to API but with additional web-specific validations)"""
        result = await self.run_api_check(check, location)
        
        # Add web-specific validations if needed
        if result.success and result.response_size_bytes:
            # Check for basic HTML structure if it's a web page
            if check.target.endswith(('.html', '/')) or not check.target.endswith(('.json', '.xml')):
                # Additional web checks could be added here
                pass
        
        return result
    
    async def run_journey_check(self, check: SyntheticCheck, location: str) -> CheckResult:
        """Run user journey check (multi-step)"""
        start_time = time.time()
        timestamp = datetime.now()
        step_results = []
        overall_success = True
        
        try:
            for step in check.checks:
                step_start = time.time()
                step_name = step.get("name", f"Step {len(step_results) + 1}")
                step_target = step.get("target")
                step_method = step.get("method", "GET")
                step_headers = step.get("headers", {})
                step_body = step.get("body")
                step_timeout = step.get("timeout", check.timeout)
                step_expected_status = step.get("expected_status_codes", [200])
                
                headers = {**check.headers, **step_headers}
                headers['User-Agent'] = 'CloudOps-SRE-Toolkit/1.0'
                
                async with self.session.request(
                    method=step_method,
                    url=step_target,
                    headers=headers,
                    data=step_body,
                    timeout=step_timeout
                ) as response:
                    content = await response.read()
                    step_response_time = (time.time() - step_start) * 1000
                    step_success = response.status in step_expected_status
                    
                    step_result = {
                        "name": step_name,
                        "target": step_target,
                        "method": step_method,
                        "status_code": response.status,
                        "response_time_ms": step_response_time,
                        "success": step_success,
                        "response_size_bytes": len(content) if content else 0
                    }
                    
                    step_results.append(step_result)
                    
                    if not step_success:
                        overall_success = False
                        break
                    
                    # Handle response data extraction for next steps if needed
                    if step.get("extract_data"):
                        # Extract data from response for use in subsequent steps
                        try:
                            response_text = content.decode('utf-8')
                            for extraction in step["extract_data"]:
                                var_name = extraction.get("name")
                                pattern = extraction.get("pattern")
                                if var_name and pattern:
                                    import re
                                    match = re.search(pattern, response_text)
                                    if match:
                                        # Store extracted value for use in subsequent steps
                                        # This would need to be implemented properly
                                        pass
                        except:
                            pass
            
            total_response_time_ms = (time.time() - start_time) * 1000
            
            return CheckResult(
                check_name=check.name,
                check_type=check.type,
                target=check.target,
                timestamp=timestamp,
                success=overall_success and total_response_time_ms <= check.expected_response_time_ms,
                response_time_ms=total_response_time_ms,
                status_code=200 if overall_success else 500,
                error_message=None if overall_success else "Journey failed",
                response_size_bytes=None,
                location=location,
                step_results=step_results
            )
        
        except Exception as e:
            total_response_time_ms = (time.time() - start_time) * 1000
            return CheckResult(
                check_name=check.name,
                check_type=check.type,
                target=check.target,
                timestamp=timestamp,
                success=False,
                response_time_ms=total_response_time_ms,
                status_code=None,
                error_message=str(e),
                response_size_bytes=None,
                location=location,
                step_results=step_results
            )
    
    async def run_check(self, check: SyntheticCheck, location: str) -> CheckResult:
        """Run a single synthetic check"""
        if check.type == "api":
            return await self.run_api_check(check, location)
        elif check.type == "web":
            return await self.run_web_check(check, location)
        elif check.type == "journey":
            return await self.run_journey_check(check, location)
        else:
            raise ValueError(f"Unknown check type: {check.type}")
    
    async def run_all_checks(self) -> List[CheckResult]:
        """Run all synthetic checks"""
        if not self.session:
            await self.create_session()
        
        tasks = []
        
        for check in self.checks:
            for location in check.locations:
                tasks.append(self.run_check(check, location))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and log them
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Error running check: {str(result)}")
            else:
                valid_results.append(result)
        
        return valid_results
    
    def analyze_results(self, results: List[CheckResult]) -> Dict[str, Any]:
        """Analyze check results"""
        if not results:
            return {}
        
        total_checks = len(results)
        successful_checks = len([r for r in results if r.success])
        failed_checks = total_checks - successful_checks
        
        response_times = [r.response_time_ms for r in results if r.success]
        average_response_time = statistics.mean(response_times) if response_times else 0
        availability_percentage = (successful_checks / total_checks) * 100 if total_checks > 0 else 0
        
        # Analyze by check name
        check_summaries = {}
        for check in self.checks:
            check_results = [r for r in results if r.check_name == check.name]
            if check_results:
                successful = len([r for r in check_results if r.success])
                total = len(check_results)
                check_response_times = [r.response_time_ms for r in check_results if r.success]
                
                check_summaries[check.name] = {
                    "total_checks": total,
                    "successful_checks": successful,
                    "failed_checks": total - successful,
                    "availability_percentage": (successful / total) * 100 if total > 0 else 0,
                    "average_response_time_ms": statistics.mean(check_response_times) if check_response_times else 0,
                    "status": "healthy" if (successful / total) >= (1 - check.alert_threshold) else "unhealthy"
                }
        
        # Generate alerts
        alerts = self._generate_alerts(results, check_summaries)
        
        return {
            "total_checks": total_checks,
            "successful_checks": successful_checks,
            "failed_checks": failed_checks,
            "average_response_time_ms": average_response_time,
            "availability_percentage": availability_percentage,
            "check_summaries": check_summaries,
            "alerts": alerts
        }
    
    def _generate_alerts(self, results: List[CheckResult], check_summaries: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate alerts based on results"""
        alerts = []
        
        # Check for failed checks
        failed_results = [r for r in results if not r.success]
        if failed_results:
            alerts.append({
                "type": "check_failure",
                "severity": "critical",
                "message": f"{len(failed_results)} synthetic checks failed",
                "details": [{"check": r.check_name, "location": r.location, "error": r.error_message} for r in failed_results]
            })
        
        # Check for high response times
        slow_checks = [r for r in results if r.success and r.response_time_ms > 5000]
        if slow_checks:
            alerts.append({
                "type": "slow_response",
                "severity": "warning",
                "message": f"{len(slow_checks)} checks have slow response times",
                "details": [{"check": r.check_name, "location": r.location, "response_time": r.response_time_ms} for r in slow_checks]
            })
        
        # Check availability thresholds
        for check_name, summary in check_summaries.items():
            if summary["availability_percentage"] < 95:  # Less than 95% availability
                alerts.append({
                    "type": "low_availability",
                    "severity": "critical" if summary["availability_percentage"] < 90 else "warning",
                    "message": f"Check {check_name} has low availability: {summary['availability_percentage']:.1f}%",
                    "details": {"check": check_name, "availability": summary["availability_percentage"]}
                })
        
        return alerts
    
    def generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        if not analysis:
            return ["No data available for analysis"]
        
        availability = analysis.get("availability_percentage", 0)
        avg_response_time = analysis.get("average_response_time_ms", 0)
        
        if availability < 99:
            recommendations.append(f"Low availability ({availability:.1f}%). Investigate failed checks and improve reliability.")
        
        if avg_response_time > 3000:
            recommendations.append(f"High average response time ({avg_response_time:.0f}ms). Consider performance optimization.")
        
        # Check-specific recommendations
        check_summaries = analysis.get("check_summaries", {})
        for check_name, summary in check_summaries.items():
            if summary["status"] == "unhealthy":
                recommendations.append(f"Check '{check_name}' is unhealthy. Review configuration and target availability.")
        
        # General recommendations
        recommendations.append("Set up automated alerting for synthetic monitoring failures.")
        recommendations.append("Implement retry logic for transient failures.")
        recommendations.append("Consider monitoring from multiple geographic locations.")
        
        return recommendations
    
    async def send_alerts(self, alerts: List[Dict[str, Any]]):
        """Send alerts to configured channels"""
        if not alerts:
            return
        
        for alert in alerts:
            message = f"🚨 Synthetic Monitoring Alert: {alert['message']}"
            
            # Send webhook
            webhook_url = self.config.get("alerts", {}).get("webhook_url")
            if webhook_url:
                await self._send_webhook_alert(webhook_url, alert, message)
            
            # Send Slack notification
            slack_webhook = self.config.get("alerts", {}).get("slack_webhook")
            if slack_webhook:
                await self._send_slack_alert(slack_webhook, alert, message)
    
    async def _send_webhook_alert(self, url: str, alert: Dict[str, Any], message: str):
        """Send alert via webhook"""
        try:
            payload = {
                "timestamp": datetime.now().isoformat(),
                "alert": alert,
                "message": message,
                "source": "synthetic-monitoring"
            }
            
            async with self.session.post(url, json=payload) as response:
                if response.status == 200:
                    logger.info("Webhook alert sent successfully")
                else:
                    logger.error(f"Failed to send webhook alert: {response.status}")
        except Exception as e:
            logger.error(f"Error sending webhook alert: {str(e)}")
    
    async def _send_slack_alert(self, url: str, alert: Dict[str, Any], message: str):
        """Send alert to Slack"""
        try:
            color = {
                "critical": "danger",
                "warning": "warning",
                "info": "good"
            }.get(alert.get("severity", "warning"), "warning")
            
            payload = {
                "attachments": [{
                    "color": color,
                    "title": "Synthetic Monitoring Alert",
                    "text": message,
                    "fields": [
                        {"title": "Severity", "value": alert.get("severity", "unknown"), "short": true},
                        {"title": "Type", "value": alert.get("type", "unknown"), "short": true}
                    ],
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
    
    async def run_continuous_monitoring(self, duration_minutes: int = None):
        """Run continuous monitoring"""
        if duration_minutes is None:
            duration_minutes = 60  # Default 1 hour
        
        logger.info(f"Starting continuous synthetic monitoring for {duration_minutes} minutes")
        
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        
        while datetime.now() < end_time:
            try:
                logger.info("Running synthetic checks...")
                results = await self.run_all_checks()
                analysis = self.analyze_results(results)
                
                # Store results
                self.results_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "results": [asdict(r) for r in results],
                    "analysis": analysis
                })
                
                # Send alerts
                await self.send_alerts(analysis.get("alerts", []))
                
                # Generate and save report
                await self.generate_and_save_report(results, analysis)
                
                logger.info(f"Check cycle completed. Availability: {analysis.get('availability_percentage', 0):.1f}%")
                
                # Wait for next cycle (minimum 1 minute)
                wait_time = max(60, min(check.frequency_minutes for check in self.checks) * 60)
                if datetime.now() + timedelta(seconds=wait_time) < end_time:
                    await asyncio.sleep(wait_time)
                
            except Exception as e:
                logger.error(f"Error during monitoring cycle: {str(e)}")
                await asyncio.sleep(60)
        
        logger.info("Continuous monitoring completed")
    
    async def generate_and_save_report(self, results: List[CheckResult], analysis: Dict[str, Any]):
        """Generate and save monitoring report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        recommendations = self.generate_recommendations(analysis)
        
        report = MonitoringReport(
            timestamp=datetime.now().isoformat(),
            total_checks=analysis.get("total_checks", 0),
            successful_checks=analysis.get("successful_checks", 0),
            failed_checks=analysis.get("failed_checks", 0),
            average_response_time_ms=analysis.get("average_response_time_ms", 0),
            availability_percentage=analysis.get("availability_percentage", 0),
            check_results=results,
            check_summaries=analysis.get("check_summaries", {}),
            alerts=analysis.get("alerts", []),
            recommendations=recommendations
        )
        
        # Save JSON report
        json_file = f"synthetic_monitoring_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        
        logger.info(f"Report saved to: {json_file}")
        
        # Generate dashboard if configured
        if "dashboard" in self.config.get("output", {}).get("format", []):
            self.generate_dashboard()
    
    def generate_dashboard(self):
        """Generate monitoring dashboard"""
        if not self.results_history:
            logger.warning("No historical data available for dashboard")
            return
        
        # Prepare data for visualization
        timestamps = [datetime.fromisoformat(d["timestamp"]) for d in self.results_history]
        availabilities = [d["analysis"].get("availability_percentage", 0) for d in self.results_history]
        response_times = [d["analysis"].get("average_response_time_ms", 0) for d in self.results_history]
        
        # Create dashboard
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('Synthetic Monitoring Dashboard', fontsize=16)
        
        # 1. Availability over time
        axes[0, 0].plot(timestamps, availabilities, marker='o', linewidth=2, color='green')
        axes[0, 0].set_title('Availability Over Time')
        axes[0, 0].set_ylabel('Availability (%)')
        axes[0, 0].tick_params(axis='x', rotation=45)
        axes[0, 0].grid(True, alpha=0.3)
        axes[0, 0].set_ylim(0, 100)
        
        # 2. Response time over time
        axes[0, 1].plot(timestamps, response_times, marker='o', linewidth=2, color='blue')
        axes[0, 1].set_title('Average Response Time Over Time')
        axes[0, 1].set_ylabel('Response Time (ms)')
        axes[0, 1].tick_params(axis='x', rotation=45)
        axes[0, 1].grid(True, alpha=0.3)
        
        # 3. Current check status
        if self.results_history:
            latest_data = self.results_history[-1]["analysis"].get("check_summaries", {})
            check_names = list(latest_data.keys())
            check_availabilities = [latest_data[name]["availability_percentage"] for name in check_names]
            
            colors = ['green' if avail >= 95 else 'orange' if avail >= 90 else 'red' for avail in check_availabilities]
            axes[1, 0].bar(check_names, check_availabilities, color=colors)
            axes[1, 0].set_title('Current Check Availability')
            axes[1, 0].set_ylabel('Availability (%)')
            axes[1, 0].tick_params(axis='x', rotation=45)
            axes[1, 0].set_ylim(0, 100)
        
        # 4. Alert summary
        if self.results_history:
            alert_counts = [len(d["analysis"].get("alerts", [])) for d in self.results_history]
            axes[1, 1].plot(timestamps, alert_counts, marker='o', linewidth=2, color='red')
            axes[1, 1].set_title('Alert Count Over Time')
            axes[1, 1].set_ylabel('Number of Alerts')
            axes[1, 1].tick_params(axis='x', rotation=45)
            axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        dashboard_file = f"synthetic_monitoring_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(dashboard_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Dashboard saved to: {dashboard_file}")

async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Run synthetic monitoring')
    parser.add_argument('--config', type=str, default='config/synthetic_monitoring_config.json', 
                       help='Configuration file path')
    parser.add_argument('--mode', choices=['single', 'continuous'], default='single', help='Monitoring mode')
    parser.add_argument('--duration', type=int, help='Monitoring duration in minutes (continuous mode)')
    parser.add_argument('--output-format', nargs='+', default=['json'], 
                       choices=['json', 'csv', 'dashboard'], help='Output formats')
    
    args = parser.parse_args()
    
    try:
        monitor = SyntheticMonitor(args.config)
        
        if args.mode == 'single':
            logger.info("Running single synthetic monitoring cycle...")
            await monitor.create_session()
            
            results = await monitor.run_all_checks()
            analysis = monitor.analyze_results(results)
            
            # Print summary
            print(f"\n=== Synthetic Monitoring Summary ===")
            print(f"Total checks: {analysis.get('total_checks', 0)}")
            print(f"Successful: {analysis.get('successful_checks', 0)}")
            print(f"Failed: {analysis.get('failed_checks', 0)}")
            print(f"Availability: {analysis.get('availability_percentage', 0):.1f}%")
            if analysis.get('average_response_time_ms'):
                print(f"Average response time: {analysis['average_response_time_ms']:.0f}ms")
            
            await monitor.generate_and_save_report(results, analysis)
            await monitor.close_session()
            
        else:
            await monitor.run_continuous_monitoring(args.duration)
            await monitor.close_session()
        
        logger.info("Synthetic monitoring completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during synthetic monitoring: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
