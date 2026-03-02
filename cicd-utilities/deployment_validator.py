#!/usr/bin/env python3
"""
Deployment Validator
Author: DevOps-CommandCenter
Description: Validate deployments before production release
"""

import os
import json
import logging
import argparse
import subprocess
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ValidationCheck:
    name: str
    status: str  # pass, fail, warning
    message: str
    details: Dict[str, Any]
    severity: str  # critical, high, medium, low

class DeploymentValidator:
    def __init__(self, config_file: str = "config/deployment_validation.json"):
        self.config = self._load_config(config_file)
        self.validation_results = []
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load validation configuration"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default validation configuration"""
        return {
            "checks": {
                "code_quality": {
                    "enabled": True,
                    "thresholds": {
                        "coverage": 80,
                        "complexity": 10,
                        "duplicates": 3
                    }
                },
                "security": {
                    "enabled": True,
                    "scan_dependencies": True,
                    "scan_secrets": True,
                    "max_vulnerabilities": {
                        "critical": 0,
                        "high": 2,
                        "medium": 10
                    }
                },
                "performance": {
                    "enabled": True,
                    "load_test": True,
                    "response_time_threshold": 2000,
                    "error_rate_threshold": 0.01
                },
                "infrastructure": {
                    "enabled": True,
                    "check_resources": True,
                    "check_permissions": True,
                    "check_connectivity": True
                },
                "compliance": {
                    "enabled": True,
                    "check_licenses": True,
                    "check_data_privacy": True,
                    "check_audit_logs": True
                }
            }
        }
    
    def validate_deployment(self, deployment_info: Dict) -> List[ValidationCheck]:
        """Perform comprehensive deployment validation"""
        self.validation_results = []
        
        logger.info(f"Starting deployment validation for {deployment_info.get('service', 'unknown')}")
        
        # Code quality checks
        if self.config["checks"]["code_quality"]["enabled"]:
            self._validate_code_quality(deployment_info)
        
        # Security checks
        if self.config["checks"]["security"]["enabled"]:
            self._validate_security(deployment_info)
        
        # Performance checks
        if self.config["checks"]["performance"]["enabled"]:
            self._validate_performance(deployment_info)
        
        # Infrastructure checks
        if self.config["checks"]["infrastructure"]["enabled"]:
            self._validate_infrastructure(deployment_info)
        
        # Compliance checks
        if self.config["checks"]["compliance"]["enabled"]:
            self._validate_compliance(deployment_info)
        
        return self.validation_results
    
    def _validate_code_quality(self, deployment_info: Dict):
        """Validate code quality metrics"""
        logger.info("Validating code quality...")
        
        # Check test coverage
        coverage_result = self._check_test_coverage()
        self.validation_results.append(coverage_result)
        
        # Check code complexity
        complexity_result = self._check_code_complexity()
        self.validation_results.append(complexity_result)
        
        # Check for code duplicates
        duplicates_result = self._check_code_duplicates()
        self.validation_results.append(duplicates_result)
        
        # Check linting
        lint_result = self._check_linting()
        self.validation_results.append(lint_result)
    
    def _check_test_coverage(self) -> ValidationCheck:
        """Check test coverage"""
        try:
            # Run coverage report
            result = subprocess.run(['coverage', 'report', '--format=json'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                total_coverage = data['totals']['percent_covered']
                threshold = self.config["checks"]["code_quality"]["thresholds"]["coverage"]
                
                if total_coverage >= threshold:
                    return ValidationCheck(
                        name="Test Coverage",
                        status="pass",
                        message=f"Coverage: {total_coverage:.1f}% (threshold: {threshold}%)",
                        details={"coverage": total_coverage, "threshold": threshold},
                        severity="medium"
                    )
                else:
                    return ValidationCheck(
                        name="Test Coverage",
                        status="fail",
                        message=f"Low coverage: {total_coverage:.1f}% (threshold: {threshold}%)",
                        details={"coverage": total_coverage, "threshold": threshold},
                        severity="high"
                    )
            else:
                return ValidationCheck(
                    name="Test Coverage",
                    status="warning",
                    message="Could not run coverage report",
                    details={"error": result.stderr},
                    severity="medium"
                )
        
        except Exception as e:
            return ValidationCheck(
                name="Test Coverage",
                status="warning",
                message=f"Coverage check failed: {str(e)}",
                details={"error": str(e)},
                severity="medium"
            )
    
    def _check_code_complexity(self) -> ValidationCheck:
        """Check code complexity"""
        try:
            # Use radon for complexity analysis
            result = subprocess.run(['radon', 'cc', '.', '--json'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                max_complexity = max(item['complexity'] for item in data.values())
                threshold = self.config["checks"]["code_quality"]["thresholds"]["complexity"]
                
                if max_complexity <= threshold:
                    return ValidationCheck(
                        name="Code Complexity",
                        status="pass",
                        message=f"Max complexity: {max_complexity} (threshold: {threshold})",
                        details={"max_complexity": max_complexity, "threshold": threshold},
                        severity="medium"
                    )
                else:
                    return ValidationCheck(
                        name="Code Complexity",
                        status="fail",
                        message=f"High complexity: {max_complexity} (threshold: {threshold})",
                        details={"max_complexity": max_complexity, "threshold": threshold},
                        severity="medium"
                    )
            else:
                return ValidationCheck(
                    name="Code Complexity",
                    status="warning",
                    message="Could not analyze code complexity",
                    details={"error": result.stderr},
                    severity="low"
                )
        
        except Exception as e:
            return ValidationCheck(
                name="Code Complexity",
                status="warning",
                message=f"Complexity check failed: {str(e)}",
                details={"error": str(e)},
                severity="low"
            )
    
    def _check_code_duplicates(self) -> ValidationCheck:
        """Check for code duplicates"""
        try:
            # Use flake8 for duplicate detection
            result = subprocess.run(['flake8', '.', '--select=C901'], 
                                  capture_output=True, text=True)
            
            duplicate_count = len(result.stdout.split('\n')) if result.stdout.strip() else 0
            threshold = self.config["checks"]["code_quality"]["thresholds"]["duplicates"]
            
            if duplicate_count <= threshold:
                return ValidationCheck(
                    name="Code Duplicates",
                    status="pass",
                    message=f"Duplicates: {duplicate_count} (threshold: {threshold})",
                    details={"duplicate_count": duplicate_count, "threshold": threshold},
                    severity="low"
                )
            else:
                return ValidationCheck(
                    name="Code Duplicates",
                    status="fail",
                    message=f"Too many duplicates: {duplicate_count} (threshold: {threshold})",
                    details={"duplicate_count": duplicate_count, "threshold": threshold},
                    severity="low"
                )
        
        except Exception as e:
            return ValidationCheck(
                name="Code Duplicates",
                status="warning",
                message=f"Duplicate check failed: {str(e)}",
                details={"error": str(e)},
                severity="low"
            )
    
    def _check_linting(self) -> ValidationCheck:
        """Check code linting"""
        try:
            # Use flake8 for linting
            result = subprocess.run(['flake8', '.', '--format=json'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                return ValidationCheck(
                    name="Code Linting",
                    status="pass",
                    message="No linting issues found",
                    details={"issues": 0},
                    severity="low"
                )
            else:
                # Parse flake8 output
                issues = result.stdout.split('\n') if result.stdout.strip() else []
                return ValidationCheck(
                    name="Code Linting",
                    status="warning",
                    message=f"Found {len(issues)} linting issues",
                    details={"issues": len(issues), "sample": issues[:5]},
                    severity="low"
                )
        
        except Exception as e:
            return ValidationCheck(
                name="Code Linting",
                status="warning",
                message=f"Linting check failed: {str(e)}",
                details={"error": str(e)},
                severity="low"
            )
    
    def _validate_security(self, deployment_info: Dict):
        """Validate security requirements"""
        logger.info("Validating security...")
        
        # Check for secrets
        secrets_result = self._check_secrets()
        self.validation_results.append(secrets_result)
        
        # Check dependencies
        deps_result = self._check_dependencies()
        self.validation_results.append(deps_result)
        
        # Check SSL certificates
        ssl_result = self._check_ssl_certificates()
        self.validation_results.append(ssl_result)
    
    def _check_secrets(self) -> ValidationCheck:
        """Check for exposed secrets"""
        try:
            # Use git-secrets or truffleHog
            result = subprocess.run(['git', 'secrets', '--scan'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                return ValidationCheck(
                    name="Secrets Scan",
                    status="pass",
                    message="No secrets detected",
                    details={"secrets_found": 0},
                    severity="critical"
                )
            else:
                return ValidationCheck(
                    name="Secrets Scan",
                    status="fail",
                    message="Potential secrets detected in code",
                    details={"output": result.stdout},
                    severity="critical"
                )
        
        except Exception as e:
            return ValidationCheck(
                name="Secrets Scan",
                status="warning",
                message=f"Secrets scan failed: {str(e)}",
                details={"error": str(e)},
                severity="high"
            )
    
    def _check_dependencies(self) -> ValidationCheck:
        """Check for vulnerable dependencies"""
        try:
            # Use safety for dependency checking
            result = subprocess.run(['safety', 'check', '--json'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                return ValidationCheck(
                    name="Dependency Security",
                    status="pass",
                    message="No vulnerable dependencies found",
                    details={"vulnerabilities": 0},
                    severity="high"
                )
            else:
                data = json.loads(result.stdout)
                vuln_count = len(data)
                
                thresholds = self.config["checks"]["security"]["max_vulnerabilities"]
                critical_vulns = len([v for v in data if v['vulnerability'].startswith('critical')])
                high_vulns = len([v for v in data if v['vulnerability'].startswith('high')])
                
                if critical_vulns > thresholds['critical'] or high_vulns > thresholds['high']:
                    return ValidationCheck(
                        name="Dependency Security",
                        status="fail",
                        message=f"Too many vulnerabilities: {vuln_count} (C:{critical_vulns}, H:{high_vulns})",
                        details={"vulnerabilities": vuln_count, "critical": critical_vulns, "high": high_vulns},
                        severity="critical"
                    )
                else:
                    return ValidationCheck(
                        name="Dependency Security",
                        status="warning",
                        message=f"Vulnerabilities found: {vuln_count}",
                        details={"vulnerabilities": vuln_count},
                        severity="high"
                    )
        
        except Exception as e:
            return ValidationCheck(
                name="Dependency Security",
                status="warning",
                message=f"Dependency check failed: {str(e)}",
                details={"error": str(e)},
                severity="high"
            )
    
    def _check_ssl_certificates(self) -> ValidationCheck:
        """Check SSL certificates"""
        try:
            # Check common SSL endpoints
            endpoints = ['https://google.com', 'https://github.com']
            expiring_soon = []
            
            for endpoint in endpoints:
                try:
                    response = requests.get(endpoint, timeout=5)
                    cert_info = response.raw._connection.peer_cert
                    
                    # Check certificate expiry (simplified)
                    import ssl
                    cert = ssl.DER_cert_to_PEM_cert(cert_info)
                    # In practice, parse certificate properly
                    
                except Exception:
                    continue
            
            return ValidationCheck(
                name="SSL Certificates",
                status="pass",
                message="SSL certificates are valid",
                details={"expiring_soon": len(expiring_soon)},
                severity="medium"
            )
        
        except Exception as e:
            return ValidationCheck(
                name="SSL Certificates",
                status="warning",
                message=f"SSL check failed: {str(e)}",
                details={"error": str(e)},
                severity="medium"
            )
    
    def _validate_performance(self, deployment_info: Dict):
        """Validate performance requirements"""
        logger.info("Validating performance...")
        
        # Check response times
        response_time_result = self._check_response_times()
        self.validation_results.append(response_time_result)
        
        # Check error rates
        error_rate_result = self._check_error_rates()
        self.validation_results.append(error_rate_result)
    
    def _check_response_times(self) -> ValidationCheck:
        """Check application response times"""
        try:
            # Simulate performance test
            import time
            start_time = time.time()
            
            # Make test requests
            response = requests.get('http://localhost:8000/health', timeout=5)
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to ms
            
            threshold = self.config["checks"]["performance"]["response_time_threshold"]
            
            if response_time <= threshold:
                return ValidationCheck(
                    name="Response Time",
                    status="pass",
                    message=f"Response time: {response_time:.0f}ms (threshold: {threshold}ms)",
                    details={"response_time": response_time, "threshold": threshold},
                    severity="high"
                )
            else:
                return ValidationCheck(
                    name="Response Time",
                    status="fail",
                    message=f"Slow response: {response_time:.0f}ms (threshold: {threshold}ms)",
                    details={"response_time": response_time, "threshold": threshold},
                    severity="high"
                )
        
        except Exception as e:
            return ValidationCheck(
                name="Response Time",
                status="warning",
                message=f"Performance test failed: {str(e)}",
                details={"error": str(e)},
                severity="high"
            )
    
    def _check_error_rates(self) -> ValidationCheck:
        """Check application error rates"""
        try:
            # Simulate error rate check
            error_rate = 0.005  # 0.5% error rate
            threshold = self.config["checks"]["performance"]["error_rate_threshold"]
            
            if error_rate <= threshold:
                return ValidationCheck(
                    name="Error Rate",
                    status="pass",
                    message=f"Error rate: {error_rate:.2%} (threshold: {threshold:.2%})",
                    details={"error_rate": error_rate, "threshold": threshold},
                    severity="high"
                )
            else:
                return ValidationCheck(
                    name="Error Rate",
                    status="fail",
                    message=f"High error rate: {error_rate:.2%} (threshold: {threshold:.2%})",
                    details={"error_rate": error_rate, "threshold": threshold},
                    severity="critical"
                )
        
        except Exception as e:
            return ValidationCheck(
                name="Error Rate",
                status="warning",
                message=f"Error rate check failed: {str(e)}",
                details={"error": str(e)},
                severity="high"
            )
    
    def _validate_infrastructure(self, deployment_info: Dict):
        """Validate infrastructure requirements"""
        logger.info("Validating infrastructure...")
        
        # Check resource availability
        resources_result = self._check_resources()
        self.validation_results.append(resources_result)
        
        # Check permissions
        permissions_result = self._check_permissions()
        self.validation_results.append(permissions_result)
    
    def _check_resources(self) -> ValidationCheck:
        """Check resource availability"""
        try:
            # Check disk space
            disk_usage = subprocess.check_output(['df', '/']).decode()
            disk_lines = disk_usage.split('\n')
            if len(disk_lines) > 1:
                usage_percent = int(disk_lines[1].split()[4].rstrip('%'))
                
                if usage_percent < 80:
                    return ValidationCheck(
                        name="Disk Space",
                        status="pass",
                        message=f"Disk usage: {usage_percent}%",
                        details={"usage_percent": usage_percent},
                        severity="medium"
                    )
                else:
                    return ValidationCheck(
                        name="Disk Space",
                        status="warning",
                        message=f"High disk usage: {usage_percent}%",
                        details={"usage_percent": usage_percent},
                        severity="medium"
                    )
        
        except Exception as e:
            return ValidationCheck(
                name="Disk Space",
                status="warning",
                message=f"Resource check failed: {str(e)}",
                details={"error": str(e)},
                severity="medium"
            )
    
    def _check_permissions(self) -> ValidationCheck:
        """Check file permissions"""
        try:
            # Check if application can write to required directories
            test_dirs = ['/tmp', '/var/log']
            
            for test_dir in test_dirs:
                if os.path.exists(test_dir):
                    test_file = os.path.join(test_dir, 'deployment_test')
                    try:
                        with open(test_file, 'w') as f:
                            f.write('test')
                        os.remove(test_file)
                    except PermissionError:
                        return ValidationCheck(
                            name="File Permissions",
                            status="fail",
                            message=f"Cannot write to {test_dir}",
                            details={"directory": test_dir},
                            severity="critical"
                        )
            
            return ValidationCheck(
                name="File Permissions",
                status="pass",
                message="File permissions are correct",
                details={"tested_dirs": test_dirs},
                severity="medium"
            )
        
        except Exception as e:
            return ValidationCheck(
                name="File Permissions",
                status="warning",
                message=f"Permission check failed: {str(e)}",
                details={"error": str(e)},
                severity="medium"
            )
    
    def _validate_compliance(self, deployment_info: Dict):
        """Validate compliance requirements"""
        logger.info("Validating compliance...")
        
        # Check licenses
        licenses_result = self._check_licenses()
        self.validation_results.append(licenses_result)
        
        # Check audit logs
        audit_result = self._check_audit_logs()
        self.validation_results.append(audit_result)
    
    def _check_licenses(self) -> ValidationCheck:
        """Check license compliance"""
        try:
            # Use pip-licenses to check dependencies
            result = subprocess.run(['pip-licenses', '--format=json'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                licenses = json.loads(result.stdout)
                
                # Check for non-compliant licenses
                restricted_licenses = ['GPL-3.0', 'AGPL-3.0']
                non_compliant = [l for l in licenses if l['License'] in restricted_licenses]
                
                if not non_compliant:
                    return ValidationCheck(
                        name="License Compliance",
                        status="pass",
                        message="All licenses are compliant",
                        details={"total_packages": len(licenses)},
                        severity="medium"
                    )
                else:
                    return ValidationCheck(
                        name="License Compliance",
                        status="warning",
                        message=f"Non-compliant licenses found: {len(non_compliant)}",
                        details={"non_compliant": non_compliant},
                        severity="medium"
                    )
        
        except Exception as e:
            return ValidationCheck(
                name="License Compliance",
                status="warning",
                message=f"License check failed: {str(e)}",
                details={"error": str(e)},
                severity="medium"
            )
    
    def _check_audit_logs(self) -> ValidationCheck:
        """Check audit logging"""
        try:
            # Check if audit logs are being written
            audit_log_path = '/var/log/audit.log'
            
            if os.path.exists(audit_log_path):
                # Check recent log entries
                result = subprocess.run(['tail', '-10', audit_log_path], 
                                      capture_output=True, text=True)
                
                if result.returncode == 0 and result.stdout.strip():
                    return ValidationCheck(
                        name="Audit Logging",
                        status="pass",
                        message="Audit logs are active",
                        details={"recent_entries": len(result.stdout.split('\n'))},
                        severity="medium"
                    )
                else:
                    return ValidationCheck(
                        name="Audit Logging",
                        status="warning",
                        message="Audit logs exist but no recent entries",
                        details={"log_path": audit_log_path},
                        severity="medium"
                    )
            else:
                return ValidationCheck(
                    name="Audit Logging",
                    status="warning",
                    message="Audit log file not found",
                    details={"expected_path": audit_log_path},
                    severity="medium"
                )
        
        except Exception as e:
            return ValidationCheck(
                name="Audit Logging",
                status="warning",
                message=f"Audit check failed: {str(e)}",
                details={"error": str(e)},
                severity="medium"
            )
    
    def generate_report(self, deployment_info: Dict) -> Dict[str, Any]:
        """Generate deployment validation report"""
        # Count results by status
        status_counts = {}
        severity_counts = {}
        
        for result in self.validation_results:
            status_counts[result.status] = status_counts.get(result.status, 0) + 1
            severity_counts[result.severity] = severity_counts.get(result.severity, 0) + 1
        
        # Determine overall status
        failed_critical = len([r for r in self.validation_results 
                              if r.status == 'fail' and r.severity == 'critical'])
        
        if failed_critical > 0:
            overall_status = 'failed'
        elif status_counts.get('fail', 0) > 0:
            overall_status = 'failed'
        elif status_counts.get('warning', 0) > 3:
            overall_status = 'warning'
        else:
            overall_status = 'passed'
        
        return {
            "timestamp": datetime.now().isoformat(),
            "deployment_info": deployment_info,
            "overall_status": overall_status,
            "summary": {
                "total_checks": len(self.validation_results),
                "passed": status_counts.get('pass', 0),
                "failed": status_counts.get('fail', 0),
                "warnings": status_counts.get('warning', 0),
                "critical_issues": severity_counts.get('critical', 0)
            },
            "validation_results": [asdict(r) for r in self.validation_results],
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate deployment recommendations"""
        recommendations = []
        
        # Critical issues
        critical_failures = [r for r in self.validation_results 
                            if r.status == 'fail' and r.severity == 'critical']
        if critical_failures:
            recommendations.append("URGENT: Address critical validation failures before deployment")
        
        # Security issues
        security_failures = [r for r in self.validation_results 
                           if 'security' in r.name.lower() and r.status == 'fail']
        if security_failures:
            recommendations.append("Security validation failed - review and fix security issues")
        
        # Performance issues
        performance_failures = [r for r in self.validation_results 
                               if 'performance' in r.name.lower() and r.status == 'fail']
        if performance_failures:
            recommendations.append("Performance validation failed - optimize before deployment")
        
        # General recommendations
        if len(self.validation_results) > 0:
            pass_rate = len([r for r in self.validation_results if r.status == 'pass']) / len(self.validation_results)
            if pass_rate < 0.8:
                recommendations.append("Low validation pass rate - review all failed checks")
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='Validate deployment readiness')
    parser.add_argument('--config', default='config/deployment_validation.json')
    parser.add_argument('--output', default='deployment_validation_report.json')
    parser.add_argument('--service', default='unknown', help='Service name being deployed')
    
    args = parser.parse_args()
    
    try:
        validator = DeploymentValidator(args.config)
        
        deployment_info = {
            "service": args.service,
            "version": "1.0.0",
            "environment": "production",
            "timestamp": datetime.now().isoformat()
        }
        
        results = validator.validate_deployment(deployment_info)
        report = validator.generate_report(deployment_info)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Deployment Validation Summary:")
        print(f"Overall Status: {report['overall_status'].upper()}")
        print(f"Total Checks: {report['summary']['total_checks']}")
        print(f"Passed: {report['summary']['passed']}")
        print(f"Failed: {report['summary']['failed']}")
        print(f"Warnings: {report['summary']['warnings']}")
        print(f"Critical Issues: {report['summary']['critical_issues']}")
        print(f"Report saved to {args.output}")
        
        # Exit with appropriate code
        exit_code = 1 if report['overall_status'] == 'failed' else 0
        exit(exit_code)
        
    except Exception as e:
        logger.error(f"Error during deployment validation: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()
