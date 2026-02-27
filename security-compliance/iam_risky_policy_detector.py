#!/usr/bin/env python3
"""
IAM Risky Policy Detector
Author: CloudOps-SRE-Toolkit
Description: Detect risky IAM policies and permissions across cloud providers
"""

import boto3
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PolicyRisk:
    policy_name: str
    policy_type: str
    risk_level: str
    risky_actions: List[str]
    risk_reason: str
    recommendation: str
    attached_entities: List[str]

class IAMRiskDetector:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.risky_patterns = self._load_risky_patterns()
    
    def _load_risky_patterns(self) -> Dict[str, Dict]:
        return {
            "admin_access": {
                "actions": ["*:*"],
                "risk_level": "critical",
                "reason": "Full administrative access",
                "recommendation": "Use principle of least privilege - grant only necessary permissions"
            },
            "wildcard_services": {
                "actions": ["*:*"],
                "risk_level": "high",
                "reason": "Wildcard access to all services",
                "recommendation": "Specify exact services and actions needed"
            },
            "dangerous_services": {
                "actions": [
                    "iam:*", "s3:*", "ec2:*", "lambda:*",
                    "cloudtrail:*", "aws-marketplace:*",
                    "aws-portal:*", "directconnect:*"
                ],
                "risk_level": "high",
                "reason": "Access to critical infrastructure services",
                "recommendation": "Restrict access to specific actions within services"
            },
            "data_destruction": {
                "actions": [
                    "s3:Delete*", "ec2:Terminate*", "rds:Delete*",
                    "lambda:DeleteFunction", "cloudformation:DeleteStack"
                ],
                "risk_level": "medium",
                "reason": "Ability to delete critical resources",
                "recommendation": "Add conditions and approvals for destructive actions"
            },
            "privilege_escalation": {
                "actions": [
                    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
                    "iam:AttachUserPolicy", "iam:AttachRolePolicy",
                    "iam:PutUserPolicy", "iam:PutRolePolicy"
                ],
                "risk_level": "high",
                "reason": "Potential for privilege escalation",
                "recommendation": "Restrict policy modification permissions"
            }
        }
    
    def analyze_policies(self) -> List[PolicyRisk]:
        risks = []
        
        # Analyze managed policies
        managed_policies = self.iam.list_policies(Scope='Local', OnlyAttached=True)
        for policy in managed_policies['Policies']:
            policy_risks = self._analyze_policy(policy['PolicyName'], 'managed')
            risks.extend(policy_risks)
        
        # Analyze inline policies for users
        users = self.iam.list_users()
        for user in users['Users']:
            inline_policies = self.iam.list_user_policies(UserName=user['UserName'])
            for policy_name in inline_policies['PolicyNames']:
                policy_risks = self._analyze_inline_policy(policy_name, 'user_inline', user['UserName'])
                risks.extend(policy_risks)
        
        # Analyze inline policies for roles
        roles = self.iam.list_roles()
        for role in roles['Roles']:
            inline_policies = self.iam.list_role_policies(RoleName=role['RoleName'])
            for policy_name in inline_policies['PolicyNames']:
                policy_risks = self._analyze_inline_policy(policy_name, 'role_inline', role['RoleName'])
                risks.extend(policy_risks)
        
        return risks
    
    def _analyze_policy(self, policy_name: str, policy_type: str) -> List[PolicyRisk]:
        risks = []
        
        try:
            policy_version = self.iam.get_policy(PolicyArn=f"arn:aws:iam::{self._get_account_id()}:policy/{policy_name}")
            version_id = policy_version['Policy']['DefaultVersionId']
            
            policy_doc = self.iam.get_policy_version(
                PolicyArn=f"arn:aws:iam::{self._get_account_id()}:policy/{policy_name}",
                VersionId=version_id
            )
            
            attached_entities = self._get_policy_attachments(policy_name)
            risks.extend(self._analyze_policy_document(policy_name, policy_type, policy_doc['PolicyVersion']['Document'], attached_entities))
        
        except Exception as e:
            logger.error(f"Error analyzing policy {policy_name}: {str(e)}")
        
        return risks
    
    def _analyze_inline_policy(self, policy_name: str, policy_type: str, entity_name: str) -> List[PolicyRisk]:
        risks = []
        
        try:
            if policy_type == 'user_inline':
                policy_doc = self.iam.get_user_policy(UserName=entity_name, PolicyName=policy_name)
                attached_entities = [f"user:{entity_name}"]
            else:  # role_inline
                policy_doc = self.iam.get_role_policy(RoleName=entity_name, PolicyName=policy_name)
                attached_entities = [f"role:{entity_name}"]
            
            risks.extend(self._analyze_policy_document(policy_name, policy_type, policy_doc['PolicyDocument'], attached_entities))
        
        except Exception as e:
            logger.error(f"Error analyzing inline policy {policy_name}: {str(e)}")
        
        return risks
    
    def _analyze_policy_document(self, policy_name: str, policy_type: str, policy_doc: Dict, attached_entities: List[str]) -> List[PolicyRisk]:
        risks = []
        
        for statement in policy_doc.get('Statement', []):
            if isinstance(statement, dict):
                effect = statement.get('Effect', 'Allow')
                if effect == 'Allow':
                    actions = self._flatten_actions(statement.get('Action', []))
                    
                    for pattern_name, pattern_config in self.risky_patterns.items():
                        risky_actions = []
                        for action in actions:
                            if self._matches_pattern(action, pattern_config['actions']):
                                risky_actions.append(action)
                        
                        if risky_actions:
                            risk = PolicyRisk(
                                policy_name=policy_name,
                                policy_type=policy_type,
                                risk_level=pattern_config['risk_level'],
                                risky_actions=risky_actions,
                                risk_reason=pattern_config['reason'],
                                recommendation=pattern_config['recommendation'],
                                attached_entities=attached_entities
                            )
                            risks.append(risk)
        
        return risks
    
    def _flatten_actions(self, actions) -> List[str]:
        if isinstance(actions, str):
            return [actions]
        elif isinstance(actions, list):
            return actions
        return []
    
    def _matches_pattern(self, action: str, pattern_actions: List[str]) -> bool:
        for pattern in pattern_actions:
            if pattern == "*:*" and action == "*:*":
                return True
            elif pattern.endswith(":*") and action.startswith(pattern.split(":*")[0] + ":"):
                return True
            elif pattern.startswith("*:") and action.endswith(":" + pattern.split("*:")[1]):
                return True
            elif pattern == action:
                return True
        return False
    
    def _get_account_id(self) -> str:
        try:
            return boto3.client('sts').get_caller_identity()['Account']
        except:
            return "unknown"
    
    def _get_policy_attachments(self, policy_name: str) -> List[str]:
        attached_entities = []
        
        try:
            # Check users
            users = self.iam.list_users()
            for user in users['Users']:
                attached_policies = self.iam.list_attached_user_policies(UserName=user['UserName'])
                for policy in attached_policies['AttachedPolicies']:
                    if policy['PolicyName'] == policy_name:
                        attached_entities.append(f"user:{user['UserName']}")
            
            # Check roles
            roles = self.iam.list_roles()
            for role in roles['Roles']:
                attached_policies = self.iam.list_attached_role_policies(RoleName=role['RoleName'])
                for policy in attached_policies['AttachedPolicies']:
                    if policy['PolicyName'] == policy_name:
                        attached_entities.append(f"role:{role['RoleName']}")
        
        except Exception as e:
            logger.error(f"Error getting attachments for {policy_name}: {str(e)}")
        
        return attached_entities
    
    def generate_report(self, risks: List[PolicyRisk]) -> Dict[str, Any]:
        risk_counts = {}
        for risk in risks:
            risk_counts[risk.risk_level] = risk_counts.get(risk.risk_level, 0) + 1
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_risky_policies": len(risks),
            "risk_breakdown": risk_counts,
            "affected_entities": len(set(entity for risk in risks for entity in risk.attached_entities)),
            "risks": [asdict(risk) for r in risks]
        }

def main():
    parser = argparse.ArgumentParser(description='Detect risky IAM policies')
    parser.add_argument('--output', default='iam_risks_report.json')
    
    args = parser.parse_args()
    
    try:
        detector = IAMRiskDetector()
        risks = detector.analyze_policies()
        report = detector.generate_report(risks)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"IAM Risk Analysis Summary:")
        print(f"Total risky policies: {report['total_risky_policies']}")
        print(f"Critical risks: {report['risk_breakdown'].get('critical', 0)}")
        print(f"High risks: {report['risk_breakdown'].get('high', 0)}")
        print(f"Medium risks: {report['risk_breakdown'].get('medium', 0)}")
        print(f"Affected entities: {report['affected_entities']}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
