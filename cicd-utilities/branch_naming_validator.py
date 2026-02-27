#!/usr/bin/env python3
"""
Branch Naming Policy Validator
Author: CloudOps-SRE-Toolkit
Description: Validate branch naming conventions in Git repositories
"""

import re
import json
import logging
import argparse
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class BranchViolation:
    branch_name: str
    violation_type: str
    expected_pattern: str
    actual_name: str
    recommendation: str
    author: str
    last_commit_date: str

class BranchNamingValidator:
    def __init__(self, config_file: str = "config/branch_policy.json"):
        self.config = self._load_config(config_file)
        self.patterns = self._load_patterns()
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "patterns": {
                "feature": "feature/[A-Z0-9-_]+",
                "bugfix": "bugfix/[A-Z0-9-_]+",
                "hotfix": "hotfix/[A-Z0-9-_]+",
                "release": "release/v[0-9]+\\.[0-9]+\\.[0-9]+",
                "docs": "docs/[A-Z0-9-_]+"
            },
            "protected_branches": ["main", "master", "develop"],
            "case_sensitive": True,
            "max_branch_length": 50
        }
    
    def _load_patterns(self) -> Dict[str, str]:
        patterns = {}
        for pattern_name, pattern in self.config.get("patterns", {}).items():
            patterns[pattern_name] = pattern
        return patterns
    
    def validate_branches(self, repo_path: str = ".") -> List[BranchViolation]:
        violations = []
        
        try:
            # Get all branches
            result = subprocess.run(
                ["git", "branch", "-a"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            branches = []
            for line in result.stdout.split('\n'):
                branch = line.strip().replace('* ', '').replace('remotes/origin/', '')
                if branch and not branch.startswith('HEAD'):
                    branches.append(branch)
            
            # Validate each branch
            for branch in branches:
                violation = self._validate_branch(branch, repo_path)
                if violation:
                    violations.append(violation)
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting branches: {str(e)}")
        
        return violations
    
    def _validate_branch(self, branch_name: str, repo_path: str) -> Optional[BranchViolation]:
        # Skip protected branches
        if branch_name in self.config.get("protected_branches", []):
            return None
        
        # Check if branch matches any pattern
        for pattern_name, pattern in self.patterns.items():
            if re.match(f"^{pattern}$", branch_name, re.IGNORECASE if not self.config.get("case_sensitive", True) else 0):
                return None  # Valid branch
        
        # Check length
        if len(branch_name) > self.config.get("max_branch_length", 50):
            return BranchViolation(
                branch_name=branch_name,
                violation_type="length",
                expected_pattern=f"Max {self.config.get('max_branch_length')} characters",
                actual_name=branch_name,
                recommendation="Shorten branch name to meet length requirements",
                author=self._get_branch_author(branch_name, repo_path),
                last_commit_date=self._get_last_commit_date(branch_name, repo_path)
            )
        
        # No pattern matched
        pattern_examples = ", ".join([f"{name}: {pattern}" for name, pattern in self.patterns.items()])
        return BranchViolation(
            branch_name=branch_name,
            violation_type="pattern",
            expected_pattern=f"One of: {pattern_examples}",
            actual_name=branch_name,
            recommendation="Rename branch to follow naming convention",
            author=self._get_branch_author(branch_name, repo_path),
            last_commit_date=self._get_last_commit_date(branch_name, repo_path)
        )
    
    def _get_branch_author(self, branch_name: str, repo_path: str) -> str:
        try:
            result = subprocess.run(
                ["git", "log", "-1", "--pretty=format:%an", branch_name],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except:
            return "unknown"
    
    def _get_last_commit_date(self, branch_name: str, repo_path: str) -> str:
        try:
            result = subprocess.run(
                ["git", "log", "-1", "--pretty=format:%ci", branch_name],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except:
            return "unknown"
    
    def generate_report(self, violations: List[BranchViolation]) -> Dict[str, Any]:
        violation_types = {}
        for violation in violations:
            violation_types[violation.violation_type] = violation_types.get(violation.violation_type, 0) + 1
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_violations": len(violations),
            "violation_types": violation_types,
            "violations": [asdict(v) for v in violations]
        }

def main():
    parser = argparse.ArgumentParser(description='Validate branch naming conventions')
    parser.add_argument('--repo-path', default='.', help='Git repository path')
    parser.add_argument('--config', default='config/branch_policy.json')
    parser.add_argument('--output', default='branch_naming_report.json')
    
    args = parser.parse_args()
    
    try:
        validator = BranchNamingValidator(args.config)
        violations = validator.validate_branches(args.repo_path)
        report = validator.generate_report(violations)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Branch Naming Validation Summary:")
        print(f"Total violations: {report['total_violations']}")
        print(f"Pattern violations: {report['violation_types'].get('pattern', 0)}")
        print(f"Length violations: {report['violation_types'].get('length', 0)}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
