#!/usr/bin/env python3
"""
Secrets Exposure Scanner
Author: CloudOps-SRE-Toolkit
Description: Scan code and configurations for exposed secrets and sensitive data
"""

import os
import re
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SecretFinding:
    file_path: str
    line_number: int
    secret_type: str
    secret_value: str
    context: str
    severity: str

class SecretsScanner:
    def __init__(self):
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> Dict[str, Dict]:
        return {
            "aws_access_key": {
                "pattern": r'AKIA[0-9A-Z]{16}',
                "severity": "critical",
                "description": "AWS Access Key ID"
            },
            "aws_secret_key": {
                "pattern": r'[A-Za-z0-9/+=]{40}',
                "severity": "critical",
                "description": "AWS Secret Access Key"
            },
            "private_key": {
                "pattern": r'-----BEGIN (RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----',
                "severity": "critical",
                "description": "Private Key"
            },
            "api_key": {
                "pattern": r'[Aa][Pp][Ii][_]?[Kk][Ee][Yy].*?["\']([a-zA-Z0-9_\-]{16,})["\']',
                "severity": "high",
                "description": "API Key"
            },
            "password": {
                "pattern": r'[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd].*?["\']([^"\']{8,})["\']',
                "severity": "high",
                "description": "Password"
            },
            "database_url": {
                "pattern": r'[Dd][Aa][Tt][Aa][Bb][Aa][Ss][Ee]_[Uu][Rr][Ll].*?["\']([^"\']+)["\']',
                "severity": "high",
                "description": "Database URL"
            },
            "jwt_token": {
                "pattern": r'eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*',
                "severity": "medium",
                "description": "JWT Token"
            },
            "github_token": {
                "pattern": r'ghp_[a-zA-Z0-9]{36}',
                "severity": "critical",
                "description": "GitHub Personal Access Token"
            }
        }
    
    def scan_directory(self, directory: str, exclude_patterns: List[str] = None) -> List[SecretFinding]:
        findings = []
        exclude_patterns = exclude_patterns or ['.git', '__pycache__', 'node_modules', '.venv']
        
        for file_path in Path(directory).rglob('*'):
            if file_path.is_file() and not any(pattern in str(file_path) for pattern in exclude_patterns):
                try:
                    file_findings = self.scan_file(str(file_path))
                    findings.extend(file_findings)
                except Exception as e:
                    logger.error(f"Error scanning {file_path}: {str(e)}")
        
        return findings
    
    def scan_file(self, file_path: str) -> List[SecretFinding]:
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
                for line_num, line in enumerate(lines, 1):
                    for secret_type, config in self.patterns.items():
                        matches = re.finditer(config['pattern'], line)
                        for match in matches:
                            # Mask the actual secret value in logs
                            masked_value = self._mask_secret(match.group())
                            
                            finding = SecretFinding(
                                file_path=file_path,
                                line_number=line_num,
                                secret_type=config['description'],
                                secret_value=masked_value,
                                context=line.strip(),
                                severity=config['severity']
                            )
                            findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {str(e)}")
        
        return findings
    
    def _mask_secret(self, secret: str) -> str:
        if len(secret) <= 8:
            return '*' * len(secret)
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]
    
    def generate_report(self, findings: List[SecretFinding]) -> Dict[str, Any]:
        severity_counts = {}
        file_counts = {}
        
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            file_counts[finding.file_path] = file_counts.get(finding.file_path, 0) + 1
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "files_affected": len(file_counts),
            "findings": [asdict(f) for f in findings]
        }

def main():
    parser = argparse.ArgumentParser(description='Scan for exposed secrets')
    parser.add_argument('directory', help='Directory to scan')
    parser.add_argument('--output', default='secrets_scan_report.json')
    parser.add_argument('--exclude', nargs='+', default=['.git', '__pycache__', 'node_modules'])
    
    args = parser.parse_args()
    
    try:
        scanner = SecretsScanner()
        findings = scanner.scan_directory(args.directory, args.exclude)
        
        report = scanner.generate_report(findings)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Found {len(findings)} potential secrets in {report['files_affected']} files")
        print(f"Critical: {report['severity_breakdown'].get('critical', 0)}")
        print(f"High: {report['severity_breakdown'].get('high', 0)}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
