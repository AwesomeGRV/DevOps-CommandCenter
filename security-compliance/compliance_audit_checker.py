#!/usr/bin/env python3
"""
Compliance Audit Checker
Author: DevOps-CommandCenter
Description: Perform comprehensive compliance audits across various standards
"""

import json
import logging
import argparse
import subprocess
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ComplianceIssue:
    standard: str
    control_id: str
    requirement: str
    status: str  # compliant, non_compliant, partial
    severity: str
    description: str
    evidence: str
    recommendation: str
    affected_resources: List[str]

class ComplianceAuditChecker:
    def __init__(self, config_file: str = "config/compliance_config.json"):
        self.config = self._load_config(config_file)
        self.compliance_issues = []
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load compliance configuration"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default compliance configuration"""
        return {
            "standards": {
                "SOC2": {
                    "enabled": True,
                    "controls": [
                        {"id": "CC1.1", "name": "Security", "description": "Information security program"},
                        {"id": "CC6.1", "name": "Access Control", "description": "Logical access controls"},
                        {"id": "CC7.1", "name": "System Operations", "description": "System operations monitoring"}
                    ]
                },
                "ISO27001": {
                    "enabled": True,
                    "controls": [
                        {"id": "A.9.1.1", "name": "Access Control Policy", "description": "Access control policy"},
                        {"id": "A.12.4.1", "name": "Event Logging", "description": "Event logging"},
                        {"id": "A.14.2.5", "name": "Secure System Engineering", "description": "Secure engineering principles"}
                    ]
                },
                "GDPR": {
                    "enabled": True,
                    "controls": [
                        {"id": "Art.32", "name": "Security of Processing", "description": "Technical and organizational measures"},
                        {"id": "Art.25", "name": "Data Protection by Design", "description": "Data protection principles"}
                    ]
                },
                "PCI_DSS": {
                    "enabled": False,
                    "controls": [
                        {"id": "Req.3", "name": "Protect Cardholder Data", "description": "Protect stored cardholder data"},
                        {"id": "Req.4", "name": "Encrypt Transmission", "description": "Encrypt cardholder data"}
                    ]
                }
            },
            "checks": {
                "access_control": True,
                "encryption": True,
                "logging": True,
                "backup": True,
                "patch_management": True,
                "network_security": True
            }
        }
    
    def perform_compliance_audit(self) -> List[ComplianceIssue]:
        """Perform comprehensive compliance audit"""
        self.compliance_issues = []
        
        logger.info("Starting compliance audit...")
        
        # Perform various compliance checks
        if self.config["checks"]["access_control"]:
            self._check_access_control()
        
        if self.config["checks"]["encryption"]:
            self._check_encryption()
        
        if self.config["checks"]["logging"]:
            self._check_logging()
        
        if self.config["checks"]["backup"]:
            self._check_backup()
        
        if self.config["checks"]["patch_management"]:
            self._check_patch_management()
        
        if self.config["checks"]["network_security"]:
            self._check_network_security()
        
        # Map issues to standards
        self._map_issues_to_standards()
        
        return self.compliance_issues
    
    def _check_access_control(self):
        """Check access control compliance"""
        logger.info("Checking access control...")
        
        # Check password policies
        try:
            # Check /etc/shadow for password hashes
            if os.path.exists('/etc/shadow'):
                with open('/etc/shadow', 'r') as f:
                    shadow_content = f.read()
                
                # Check for weak password indicators
                if '!' in shadow_content or '*' in shadow_content:
                    issue = ComplianceIssue(
                        standard="MULTIPLE",
                        control_id="AC-1",
                        requirement="Password Policy",
                        status="partial",
                        severity="medium",
                        description="Some accounts may have disabled passwords",
                        evidence="Found disabled password entries in /etc/shadow",
                        recommendation="Review and enforce strong password policies",
                        affected_resources=["/etc/shadow"]
                    )
                    self.compliance_issues.append(issue)
        
        except Exception as e:
            logger.warning(f"Could not check password policies: {str(e)}")
        
        # Check SSH configuration
        ssh_config_path = "/etc/ssh/sshd_config"
        if os.path.exists(ssh_config_path):
            try:
                with open(ssh_config_path, 'r') as f:
                    ssh_config = f.read()
                
                # Check for root login
                if "PermitRootLogin yes" in ssh_config:
                    issue = ComplianceIssue(
                        standard="MULTIPLE",
                        control_id="AC-2",
                        requirement="Root Access Control",
                        status="non_compliant",
                        severity="high",
                        description="Root login is permitted via SSH",
                        evidence="PermitRootLogin yes found in SSH config",
                        recommendation="Disable root login and use sudo for administrative access",
                        affected_resources=[ssh_config_path]
                    )
                    self.compliance_issues.append(issue)
                
                # Check for password authentication
                if "PasswordAuthentication yes" in ssh_config:
                    issue = ComplianceIssue(
                        standard="MULTIPLE",
                        control_id="AC-3",
                        requirement="SSH Authentication",
                        status="non_compliant",
                        severity="medium",
                        description="Password authentication is enabled for SSH",
                        evidence="PasswordAuthentication yes found in SSH config",
                        recommendation="Use key-based authentication instead of passwords",
                        affected_resources=[ssh_config_path]
                    )
                    self.compliance_issues.append(issue)
            
            except Exception as e:
                logger.warning(f"Could not check SSH configuration: {str(e)}")
    
    def _check_encryption(self):
        """Check encryption compliance"""
        logger.info("Checking encryption...")
        
        # Check for encrypted directories (simplified check)
        try:
            # Check if any directories are encrypted (ecryptfs, LUKS, etc.)
            result = subprocess.run(['mount'], capture_output=True, text=True)
            
            if result.returncode == 0:
                mount_output = result.stdout
                
                # Look for encrypted filesystem indicators
                encrypted_indicators = ['ecryptfs', 'luks', 'crypt']
                has_encryption = any(indicator in mount_output.lower() for indicator in encrypted_indicators)
                
                if not has_encryption:
                    issue = ComplianceIssue(
                        standard="MULTIPLE",
                        control_id="ENC-1",
                        requirement="Data Encryption",
                        status="partial",
                        severity="medium",
                        description="No encrypted filesystems detected",
                        evidence="Mount output shows no encrypted filesystems",
                        recommendation="Implement encryption for sensitive data",
                        affected_resources=["filesystem"]
                    )
                    self.compliance_issues.append(issue)
        
        except Exception as e:
            logger.warning(f"Could not check encryption: {str(e)}")
        
        # Check SSL/TLS configuration
        try:
            # Check for SSL certificates
            ssl_dirs = ['/etc/ssl/certs', '/etc/pki/tls/certs']
            ssl_found = False
            
            for ssl_dir in ssl_dirs:
                if os.path.exists(ssl_dir):
                    cert_files = [f for f in os.listdir(ssl_dir) if f.endswith('.crt') or f.endswith('.pem')]
                    if cert_files:
                        ssl_found = True
                        break
            
            if not ssl_found:
                issue = ComplianceIssue(
                    standard="MULTIPLE",
                    control_id="ENC-2",
                    requirement="SSL/TLS Configuration",
                    status="partial",
                    severity="medium",
                    description="No SSL certificates found in standard locations",
                    evidence="No certificate files found in SSL directories",
                    recommendation="Install SSL certificates for secure communications",
                    affected_resources=["SSL configuration"]
                )
                self.compliance_issues.append(issue)
        
        except Exception as e:
            logger.warning(f"Could not check SSL configuration: {str(e)}")
    
    def _check_logging(self):
        """Check logging compliance"""
        logger.info("Checking logging...")
        
        # Check system logging
        log_dirs = ['/var/log', '/var/log/audit']
        logging_issues = []
        
        for log_dir in log_dirs:
            if not os.path.exists(log_dir):
                logging_issues.append(f"Missing log directory: {log_dir}")
                continue
            
            # Check log directory permissions
            stat_info = os.stat(log_dir)
            permissions = oct(stat_info.st_mode)[-3:]
            
            if permissions != '755' and permissions != '750':
                logging_issues.append(f"Incorrect permissions on {log_dir}: {permissions}")
            
            # Check if logs are being written
            log_files = [f for f in os.listdir(log_dir) if os.path.isfile(os.path.join(log_dir, f))]
            
            if not log_files:
                logging_issues.append(f"No log files found in {log_dir}")
                continue
            
            # Check recent log activity
            recent_logs = 0
            for log_file in log_files[:10]:  # Check first 10 files
                log_path = os.path.join(log_dir, log_file)
                try:
                    mtime = os.path.getmtime(log_path)
                    if time.time() - mtime < 86400:  # Modified in last 24 hours
                        recent_logs += 1
                except:
                    continue
            
            if recent_logs == 0:
                logging_issues.append(f"No recent log activity in {log_dir}")
        
        if logging_issues:
            issue = ComplianceIssue(
                standard="MULTIPLE",
                control_id="LOG-1",
                requirement="System Logging",
                status="partial",
                severity="medium",
                description="Logging configuration issues detected",
                evidence="; ".join(logging_issues),
                recommendation="Ensure proper logging configuration and retention",
                affected_resources=["logging system"]
            )
            self.compliance_issues.append(issue)
    
    def _check_backup(self):
        """Check backup compliance"""
        logger.info("Checking backup...")
        
        # Check for backup scripts or configurations
        backup_indicators = [
            '/etc/cron.daily/backup',
            '/etc/cron.weekly/backup',
            '/usr/local/bin/backup',
            '/opt/backup'
        ]
        
        backup_found = False
        for indicator in backup_indicators:
            if os.path.exists(indicator):
                backup_found = True
                break
        
        if not backup_found:
            # Check for common backup software
            backup_commands = ['rsync', 'tar', 'backup', 'dump']
            backup_software = False
            
            for cmd in backup_commands:
                try:
                    subprocess.run(['which', cmd], capture_output=True, check=True)
                    backup_software = True
                    break
                except subprocess.CalledProcessError:
                    continue
            
            if not backup_software:
                issue = ComplianceIssue(
                    standard="MULTIPLE",
                    control_id="BACKUP-1",
                    requirement="Backup System",
                    status="non_compliant",
                    severity="high",
                    description="No backup system detected",
                    evidence="No backup scripts or software found",
                    recommendation="Implement regular backup procedures",
                    affected_resources=["backup system"]
                )
                self.compliance_issues.append(issue)
    
    def _check_patch_management(self):
        """Check patch management compliance"""
        logger.info("Checking patch management...")
        
        try:
            # Check last system update (Ubuntu/Debian)
            try:
                result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True)
                if result.returncode == 0:
                    updates_available = len([line for line in result.stdout.split('\n') if line.strip()])
                    
                    if updates_available > 10:
                        issue = ComplianceIssue(
                            standard="MULTIPLE",
                            control_id="PATCH-1",
                            requirement="System Updates",
                            status="partial",
                            severity="medium",
                            description=f"{updates_available} updates available",
                            evidence=f"apt list --upgradable shows {updates_available} packages",
                            recommendation="Apply system updates regularly",
                            affected_resources=["system packages"]
                        )
                        self.compliance_issues.append(issue)
            
            except:
                # Try yum/rpm for RedHat systems
                try:
                    result = subprocess.run(['yum', 'check-update'], capture_output=True, text=True)
                    if result.returncode == 100:  # Updates available
                        updates_available = len([line for line in result.stdout.split('\n') if line.strip()])
                        
                        if updates_available > 10:
                            issue = ComplianceIssue(
                                standard="MULTIPLE",
                                control_id="PATCH-1",
                                requirement="System Updates",
                                status="partial",
                                severity="medium",
                                description=f"{updates_available} updates available",
                                evidence=f"yum check-update shows {updates_available} packages",
                                recommendation="Apply system updates regularly",
                                affected_resources=["system packages"]
                            )
                            self.compliance_issues.append(issue)
                
                except:
                    pass
        
        except Exception as e:
            logger.warning(f"Could not check patch management: {str(e)}")
    
    def _check_network_security(self):
        """Check network security compliance"""
        logger.info("Checking network security...")
        
        try:
            # Check firewall status
            try:
                # Check ufw (Ubuntu)
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                if result.returncode == 0:
                    if "Status: inactive" in result.stdout:
                        issue = ComplianceIssue(
                            standard="MULTIPLE",
                            control_id="NET-1",
                            requirement="Firewall",
                            status="non_compliant",
                            severity="high",
                            description="Firewall is not active",
                            evidence="ufw status shows inactive",
                            recommendation="Enable and configure firewall",
                            affected_resources=["firewall"]
                        )
                        self.compliance_issues.append(issue)
            
            except:
                # Check iptables
                try:
                    result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                    if result.returncode == 0:
                        if len(result.stdout.strip().split('\n')) < 10:  # Very basic rules
                            issue = ComplianceIssue(
                                standard="MULTIPLE",
                                control_id="NET-1",
                                requirement="Firewall",
                                status="partial",
                                severity="medium",
                                description="Firewall rules may be insufficient",
                                evidence="iptables rules appear minimal",
                                recommendation="Review and strengthen firewall rules",
                                affected_resources=["firewall"]
                            )
                            self.compliance_issues.append(issue)
                
                except:
                    pass
        
        except Exception as e:
            logger.warning(f"Could not check network security: {str(e)}")
    
    def _map_issues_to_standards(self):
        """Map compliance issues to specific standards"""
        for issue in self.compliance_issues:
            if issue.standard == "MULTIPLE":
                # Map to enabled standards
                mapped_standards = []
                
                if self.config["standards"]["SOC2"]["enabled"]:
                    mapped_standards.append("SOC2")
                
                if self.config["standards"]["ISO27001"]["enabled"]:
                    mapped_standards.append("ISO27001")
                
                if self.config["standards"]["GDPR"]["enabled"]:
                    mapped_standards.append("GDPR")
                
                if self.config["standards"]["PCI_DSS"]["enabled"]:
                    mapped_standards.append("PCI_DSS")
                
                issue.standard = ", ".join(mapped_standards)
    
    def generate_report(self, issues: List[ComplianceIssue]) -> Dict[str, Any]:
        """Generate compliance audit report"""
        # Group by standard
        issues_by_standard = {}
        for issue in issues:
            for standard in issue.standard.split(", "):
                if standard not in issues_by_standard:
                    issues_by_standard[standard] = []
                issues_by_standard[standard].append(issue)
        
        # Group by severity
        severity_counts = {}
        for issue in issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
        
        # Calculate compliance score
        total_checks = 50  # Estimated total checks
        failed_checks = len([i for i in issues if i.status == "non_compliant"])
        partial_checks = len([i for i in issues if i.status == "partial"])
        
        compliance_score = max(0, 100 - ((failed_checks * 2 + partial_checks) * 2))
        
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_issues": len(issues),
                "severity_breakdown": severity_counts,
                "compliance_score": compliance_score,
                "standards_checked": [s for s in self.config["standards"].keys() 
                                   if self.config["standards"][s]["enabled"]]
            },
            "issues_by_standard": {
                standard: [asdict(issue) for issue in std_issues]
                for standard, std_issues in issues_by_standard.items()
            },
            "all_issues": [asdict(issue) for issue in issues],
            "recommendations": self._generate_recommendations(issues)
        }
    
    def _generate_recommendations(self, issues: List[ComplianceIssue]) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        # Group by issue type
        issue_types = {}
        for issue in issues:
            issue_type = issue.control_id.split('-')[0]
            if issue_type not in issue_types:
                issue_types[issue_type] = []
            issue_types[issue_type].append(issue)
        
        # Generate recommendations for each issue type
        if 'AC' in issue_types:  # Access Control
            recommendations.extend([
                "Implement strong password policies and regular password changes",
                "Disable direct root access and use sudo for administrative tasks",
                "Use key-based authentication instead of passwords",
                "Regularly review and remove unnecessary user accounts"
            ])
        
        if 'ENC' in issue_types:  # Encryption
            recommendations.extend([
                "Implement full disk encryption for sensitive data",
                "Use SSL/TLS for all network communications",
                "Encrypt backup data both in transit and at rest",
                "Implement key management procedures"
            ])
        
        if 'LOG' in issue_types:  # Logging
            recommendations.extend([
                "Ensure comprehensive logging is enabled for all systems",
                "Implement centralized log management",
                "Set up log rotation and retention policies",
                "Monitor logs for security events"
            ])
        
        if 'BACKUP' in issue_types:  # Backup
            recommendations.extend([
                "Implement automated backup procedures",
                "Test backup restoration regularly",
                "Store backups in secure, offsite locations",
                "Document backup and recovery procedures"
            ])
        
        if 'PATCH' in issue_types:  # Patch Management
            recommendations.extend([
                "Implement regular patch management schedule",
                "Test patches before deployment to production",
                "Maintain an inventory of system assets",
                "Monitor for security advisories"
            ])
        
        if 'NET' in issue_types:  # Network Security
            recommendations.extend([
                "Configure and enable firewall rules",
                "Implement network segmentation",
                "Use VPN for remote access",
                "Regularly scan for open ports"
            ])
        
        # General recommendations
        recommendations.extend([
            "Conduct regular security audits and assessments",
            "Document all security policies and procedures",
            "Provide security awareness training to staff",
            "Implement incident response procedures"
        ])
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='Perform compliance audit')
    parser.add_argument('--config', default='config/compliance_config.json')
    parser.add_argument('--output', default='compliance_audit_report.json')
    parser.add_argument('--standards', nargs='+', 
                       choices=['SOC2', 'ISO27001', 'GDPR', 'PCI_DSS'],
                       help='Specific standards to check')
    
    args = parser.parse_args()
    
    try:
        checker = ComplianceAuditChecker(args.config)
        
        # Override standards if specified
        if args.standards:
            for std in checker.config["standards"]:
                checker.config["standards"][std]["enabled"] = std in args.standards
        
        issues = checker.perform_compliance_audit()
        report = checker.generate_report(issues)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Compliance Audit Summary:")
        print(f"Total issues: {report['summary']['total_issues']}")
        print(f"Compliance Score: {report['summary']['compliance_score']:.1f}/100")
        print(f"Critical: {report['summary']['severity_breakdown'].get('critical', 0)}")
        print(f"High: {report['summary']['severity_breakdown'].get('high', 0)}")
        print(f"Medium: {report['summary']['severity_breakdown'].get('medium', 0)}")
        print(f"Low: {report['summary']['severity_breakdown'].get('low', 0)}")
        print(f"Standards checked: {', '.join(report['summary']['standards_checked'])}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error during compliance audit: {str(e)}")

if __name__ == "__main__":
    main()
