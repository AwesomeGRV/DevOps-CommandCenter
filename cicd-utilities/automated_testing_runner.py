#!/usr/bin/env python3
"""
Automated Testing Runner
Author: DevOps-CommandCenter
Description: Comprehensive automated testing framework for CI/CD pipelines
"""

import os
import json
import logging
import argparse
import subprocess
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import threading
import queue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    test_name: str
    test_type: str
    status: str  # passed, failed, skipped, error
    duration: float
    output: str
    error_message: str
    assertions: int
    coverage: float
    timestamp: datetime

class AutomatedTestingRunner:
    def __init__(self, config_file: str = "config/testing_config.json"):
        self.config = self._load_config(config_file)
        self.test_results = []
        self.test_queue = queue.Queue()
        self.parallel_execution = self.config.get("parallel_execution", True)
        self.max_workers = self.config.get("max_workers", 4)
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load testing configuration"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default testing configuration"""
        return {
            "parallel_execution": True,
            "max_workers": 4,
            "timeout_seconds": 300,
            "test_types": {
                "unit": {
                    "enabled": True,
                    "frameworks": ["pytest", "unittest"],
                    "commands": [
                        {"name": "python_unit_tests", "command": "python -m pytest tests/unit/ -v --cov=src"},
                        {"name": "javascript_unit_tests", "command": "npm test -- --coverage"}
                    ]
                },
                "integration": {
                    "enabled": True,
                    "frameworks": ["pytest", "jest"],
                    "commands": [
                        {"name": "api_integration_tests", "command": "python -m pytest tests/integration/ -v"},
                        {"name": "database_integration_tests", "command": "python -m pytest tests/integration/db/ -v"}
                    ]
                },
                "e2e": {
                    "enabled": True,
                    "frameworks": ["cypress", "selenium"],
                    "commands": [
                        {"name": "web_e2e_tests", "command": "npm run test:e2e"},
                        {"name": "api_e2e_tests", "command": "python -m pytest tests/e2e/ -v"}
                    ]
                },
                "performance": {
                    "enabled": True,
                    "tools": ["jmeter", "k6", "locust"],
                    "commands": [
                        {"name": "load_test", "command": "k6 run tests/performance/load_test.js"},
                        {"name": "stress_test", "command": "k6 run tests/performance/stress_test.js"}
                    ]
                },
                "security": {
                    "enabled": True,
                    "tools": ["bandit", "safety", "semgrep"],
                    "commands": [
                        {"name": "static_analysis", "command": "bandit -r src/ -f json"},
                        {"name": "dependency_scan", "command": "safety check --json"},
                        {"name": "secrets_scan", "command": "git-secrets --scan"}
                    ]
                }
            },
            "environment": {
                "setup_commands": [
                    "docker-compose -f docker-compose.test.yml up -d",
                    "sleep 10"
                ],
                "teardown_commands": [
                    "docker-compose -f docker-compose.test.yml down -v"
                ]
            },
            "notifications": {
                "slack_webhook": os.getenv("SLACK_WEBHOOK_URL"),
                "email_recipients": os.getenv("TEST_EMAIL_RECIPIENTS", "").split(",")
            }
        }
    
    def run_all_tests(self, test_types: List[str] = None) -> List[TestResult]:
        """Run all configured tests"""
        if not test_types:
            test_types = [t for t in self.config["test_types"].keys() 
                         if self.config["test_types"][t]["enabled"]]
        
        logger.info(f"Running tests for types: {test_types}")
        
        # Setup test environment
        self._setup_environment()
        
        try:
            # Run tests by type
            for test_type in test_types:
                if test_type in self.config["test_types"]:
                    self._run_test_type(test_type)
            
            # Wait for all tests to complete
            self._wait_for_completion()
            
        finally:
            # Teardown test environment
            self._teardown_environment()
        
        return self.test_results
    
    def _setup_environment(self):
        """Setup test environment"""
        logger.info("Setting up test environment...")
        
        for command in self.config["environment"]["setup_commands"]:
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    logger.warning(f"Setup command failed: {command}")
            except subprocess.TimeoutExpired:
                logger.error(f"Setup command timed out: {command}")
            except Exception as e:
                logger.error(f"Error running setup command {command}: {str(e)}")
    
    def _teardown_environment(self):
        """Teardown test environment"""
        logger.info("Tearing down test environment...")
        
        for command in self.config["environment"]["teardown_commands"]:
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    logger.warning(f"Teardown command failed: {command}")
            except subprocess.TimeoutExpired:
                logger.error(f"Teardown command timed out: {command}")
            except Exception as e:
                logger.error(f"Error running teardown command {command}: {str(e)}")
    
    def _run_test_type(self, test_type: str):
        """Run tests of a specific type"""
        logger.info(f"Running {test_type} tests...")
        
        test_config = self.config["test_types"][test_type]
        
        if self.parallel_execution:
            # Run tests in parallel
            threads = []
            for command_config in test_config["commands"]:
                thread = threading.Thread(
                    target=self._execute_test_command,
                    args=(command_config, test_type)
                )
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
                # Limit concurrent threads
                if len(threads) >= self.max_workers:
                    for t in threads:
                        t.join()
                    threads = []
            
            # Wait for remaining threads
            for thread in threads:
                thread.join()
        else:
            # Run tests sequentially
            for command_config in test_config["commands"]:
                self._execute_test_command(command_config, test_type)
    
    def _execute_test_command(self, command_config: Dict, test_type: str):
        """Execute a single test command"""
        command_name = command_config["name"]
        command = command_config["command"]
        
        logger.info(f"Executing {command_name}: {command}")
        
        start_time = time.time()
        
        try:
            # Execute test command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.config["timeout_seconds"]
            )
            
            duration = time.time() - start_time
            
            # Parse test results
            test_result = self._parse_test_result(
                command_name, test_type, result, duration
            )
            
            self.test_results.append(test_result)
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            
            test_result = TestResult(
                test_name=command_name,
                test_type=test_type,
                status="error",
                duration=duration,
                output="",
                error_message=f"Test timed out after {self.config['timeout_seconds']} seconds",
                assertions=0,
                coverage=0.0,
                timestamp=datetime.now()
            )
            
            self.test_results.append(test_result)
            
        except Exception as e:
            duration = time.time() - start_time
            
            test_result = TestResult(
                test_name=command_name,
                test_type=test_type,
                status="error",
                duration=duration,
                output="",
                error_message=f"Test execution error: {str(e)}",
                assertions=0,
                coverage=0.0,
                timestamp=datetime.now()
            )
            
            self.test_results.append(test_result)
    
    def _parse_test_result(self, test_name: str, test_type: str, 
                          result: subprocess.CompletedProcess, duration: float) -> TestResult:
        """Parse test command result"""
        output = result.stdout + result.stderr
        
        # Determine status
        if result.returncode == 0:
            status = "passed"
        else:
            status = "failed"
        
        # Extract metrics based on test type
        assertions = 0
        coverage = 0.0
        error_message = ""
        
        if test_type == "unit" or test_type == "integration":
            # Parse pytest output
            assertions = self._extract_pytest_assertions(output)
            coverage = self._extract_coverage(output)
        
        elif test_type == "e2e":
            # Parse Cypress/Selenium output
            assertions = self._extract_e2e_tests(output)
        
        elif test_type == "performance":
            # Parse performance test output
            assertions = self._extract_performance_metrics(output)
        
        elif test_type == "security":
            # Parse security scan output
            assertions = self._extract_security_issues(output)
        
        if result.returncode != 0:
            error_message = self._extract_error_message(output)
        
        return TestResult(
            test_name=test_name,
            test_type=test_type,
            status=status,
            duration=duration,
            output=output,
            error_message=error_message,
            assertions=assertions,
            coverage=coverage,
            timestamp=datetime.now()
        )
    
    def _extract_pytest_assertions(self, output: str) -> int:
        """Extract number of assertions from pytest output"""
        import re
        
        # Look for patterns like "5 passed" or "3 failed"
        patterns = [
            r'(\d+) passed',
            r'(\d+) failed',
            r'(\d+) tests',
            r'(\d+) assertions'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return int(match.group(1))
        
        return 0
    
    def _extract_coverage(self, output: str) -> float:
        """Extract coverage percentage from output"""
        import re
        
        # Look for coverage patterns
        patterns = [
            r'(\d+)% coverage',
            r'coverage: (\d+)%',
            r'TOTAL\s+\d+\s+\d+\s+(\d+)%'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return float(match.group(1))
        
        return 0.0
    
    def _extract_e2e_tests(self, output: str) -> int:
        """Extract number of E2E tests from output"""
        import re
        
        patterns = [
            r'(\d+) passing',
            r'(\d+) failing',
            r'(\d+) pending',
            r'(\d+) specs'
        ]
        
        total = 0
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                total += int(match.group(1))
        
        return total
    
    def _extract_performance_metrics(self, output: str) -> int:
        """Extract performance metrics from output"""
        # For performance tests, return number of requests or iterations
        import re
        
        patterns = [
            r'(\d+) requests',
            r'(\d+) iterations',
            r'(\d+) VUs'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return int(match.group(1))
        
        return 0
    
    def _extract_security_issues(self, output: str) -> int:
        """Extract number of security issues from output"""
        import re
        
        patterns = [
            r'(\d+) issues found',
            r'(\d+) vulnerabilities',
            r'(\d+) warnings'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return int(match.group(1))
        
        return 0
    
    def _extract_error_message(self, output: str) -> str:
        """Extract error message from output"""
        lines = output.split('\n')
        
        # Look for error patterns
        error_patterns = ['ERROR', 'FAILED', 'Exception', 'Error:']
        
        for line in lines:
            for pattern in error_patterns:
                if pattern in line:
                    return line.strip()
        
        return "Test failed - see output for details"
    
    def _wait_for_completion(self):
        """Wait for all tests to complete"""
        # This is a placeholder for more complex synchronization
        time.sleep(1)
    
    def generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        if not self.test_results:
            return {"error": "No test results available"}
        
        # Group results by test type
        results_by_type = {}
        for result in self.test_results:
            if result.test_type not in results_by_type:
                results_by_type[result.test_type] = []
            results_by_type[result.test_type].append(result)
        
        # Calculate statistics
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r.status == "passed"])
        failed_tests = len([r for r in self.test_results if r.status == "failed"])
        error_tests = len([r for r in self.test_results if r.status == "error"])
        skipped_tests = len([r for r in self.test_results if r.status == "skipped"])
        
        total_duration = sum(r.duration for r in self.test_results)
        total_assertions = sum(r.assertions for r in self.test_results)
        avg_coverage = sum(r.coverage for r in self.test_results) / total_tests if total_tests > 0 else 0
        
        # Calculate success rate
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_tests": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "errors": error_tests,
                "skipped": skipped_tests,
                "success_rate": success_rate,
                "total_duration": total_duration,
                "total_assertions": total_assertions,
                "average_coverage": avg_coverage
            },
            "results_by_type": {
                test_type: {
                    "total": len(results),
                    "passed": len([r for r in results if r.status == "passed"]),
                    "failed": len([r for r in results if r.status == "failed"]),
                    "errors": len([r for r in results if r.status == "error"]),
                    "duration": sum(r.duration for r in results),
                    "coverage": sum(r.coverage for r in results) / len(results) if results else 0
                }
                for test_type, results in results_by_type.items()
            },
            "test_results": [asdict(result) for result in self.test_results],
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate test improvement recommendations"""
        recommendations = []
        
        # Analyze test results
        failed_tests = [r for r in self.test_results if r.status == "failed"]
        error_tests = [r for r in self.test_results if r.status == "error"]
        
        if failed_tests:
            recommendations.append(f"Review and fix {len(failed_tests)} failed tests")
        
        if error_tests:
            recommendations.append(f"Investigate {len(error_tests)} test execution errors")
        
        # Check coverage
        avg_coverage = sum(r.coverage for r in self.test_results) / len(self.test_results) if self.test_results else 0
        if avg_coverage < 80:
            recommendations.append("Increase test coverage - current average is below 80%")
        
        # Check performance
        slow_tests = [r for r in self.test_results if r.duration > 60]
        if slow_tests:
            recommendations.append(f"Optimize {len(slow_tests)} slow tests (taking >60 seconds)")
        
        # Check test types
        test_types = set(r.test_type for r in self.test_results)
        missing_types = []
        
        for test_type in ["unit", "integration", "e2e", "performance", "security"]:
            if test_type not in test_types and self.config["test_types"][test_type]["enabled"]:
                missing_types.append(test_type)
        
        if missing_types:
            recommendations.append(f"Consider adding missing test types: {', '.join(missing_types)}")
        
        # General recommendations
        recommendations.extend([
            "Implement test data management for consistent test environments",
            "Add test flakiness detection and retry mechanisms",
            "Consider implementing test parallelization for faster execution",
            "Set up test result notifications and dashboards"
        ])
        
        return recommendations
    
    def send_notifications(self, report: Dict[str, Any]):
        """Send test notifications"""
        summary = report["summary"]
        
        # Send Slack notification
        slack_webhook = self.config["notifications"]["slack_webhook"]
        if slack_webhook:
            self._send_slack_notification(slack_webhook, summary)
        
        # Send email notification
        email_recipients = self.config["notifications"]["email_recipients"]
        if email_recipients and email_recipients != ['']:
            self._send_email_notification(email_recipients, summary)
    
    def _send_slack_notification(self, webhook_url: str, summary: Dict[str, Any]):
        """Send Slack notification"""
        try:
            color = "good" if summary["success_rate"] >= 90 else "warning" if summary["success_rate"] >= 70 else "danger"
            
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": "Automated Test Results",
                        "fields": [
                            {"title": "Total Tests", "value": summary["total_tests"], "short": True},
                            {"title": "Success Rate", "value": f"{summary['success_rate']:.1f}%", "short": True},
                            {"title": "Passed", "value": summary["passed"], "short": True},
                            {"title": "Failed", "value": summary["failed"], "short": True},
                            {"title": "Duration", "value": f"{summary['total_duration']:.1f}s", "short": True},
                            {"title": "Coverage", "value": f"{summary['average_coverage']:.1f}%", "short": True}
                        ],
                        "footer": "DevOps-CommandCenter",
                        "ts": int(time.time())
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            if response.status_code != 200:
                logger.warning(f"Failed to send Slack notification: {response.status_code}")
        
        except Exception as e:
            logger.error(f"Error sending Slack notification: {str(e)}")
    
    def _send_email_notification(self, recipients: List[str], summary: Dict[str, Any]):
        """Send email notification"""
        # Placeholder for email implementation
        logger.info(f"Email notification would be sent to: {recipients}")
        logger.info(f"Test summary: {summary}")

def main():
    parser = argparse.ArgumentParser(description='Run automated tests')
    parser.add_argument('--config', default='config/testing_config.json')
    parser.add_argument('--output', default='test_report.json')
    parser.add_argument('--types', nargs='+', 
                       choices=['unit', 'integration', 'e2e', 'performance', 'security'],
                       help='Specific test types to run')
    parser.add_argument('--notify', action='store_true', help='Send notifications')
    
    args = parser.parse_args()
    
    try:
        runner = AutomatedTestingRunner(args.config)
        
        # Run tests
        results = runner.run_all_tests(args.types)
        
        # Generate report
        report = runner.generate_test_report()
        
        # Save report
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Send notifications if requested
        if args.notify:
            runner.send_notifications(report)
        
        # Print summary
        summary = report["summary"]
        print(f"Automated Testing Summary:")
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Success Rate: {summary['success_rate']:.1f}%")
        print(f"Passed: {summary['passed']}")
        print(f"Failed: {summary['failed']}")
        print(f"Errors: {summary['errors']}")
        print(f"Duration: {summary['total_duration']:.1f}s")
        print(f"Average Coverage: {summary['average_coverage']:.1f}%")
        print(f"Report saved to {args.output}")
        
        # Exit with appropriate code
        exit_code = 1 if summary['failed'] > 0 or summary['errors'] > 0 else 0
        exit(exit_code)
        
    except Exception as e:
        logger.error(f"Error during test execution: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()
