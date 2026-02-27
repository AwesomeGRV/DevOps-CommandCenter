#!/usr/bin/env python3
"""
AWS Public S3 Bucket Detector
Author: CloudOps-SRE-Toolkit
Description: Detect publicly accessible S3 buckets and security risks
"""

import os
import json
import logging
import argparse
import boto3
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class S3BucketRisk:
    name: str
    region: str
    public_read: bool
    public_write: bool
    public_list: bool
    anonymous_access: bool
    risk_level: str
    recommendations: List[str]

class S3PublicDetector:
    def __init__(self):
        self.s3 = boto3.client('s3')
        self.s3control = boto3.client('s3control')
    
    def detect_public_buckets(self) -> List[S3BucketRisk]:
        risks = []
        buckets = self.s3.list_buckets()
        
        for bucket in buckets['Buckets']:
            try:
                risk = self._analyze_bucket(bucket['Name'])
                risks.append(risk)
            except Exception as e:
                logger.error(f"Error analyzing bucket {bucket['Name']}: {str(e)}")
        
        return risks
    
    def _analyze_bucket(self, bucket_name: str) -> S3BucketRisk:
        # Get bucket ACL
        acl = self.s3.get_bucket_acl(Bucket=bucket_name)
        
        # Check for public access
        public_read = self._check_public_read(acl)
        public_write = self._check_public_write(acl)
        public_list = self._check_public_list(acl)
        
        # Get bucket policy
        try:
            policy = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy_public = self._check_policy_public(policy['Policy'])
        except:
            policy_public = False
        
        # Determine risk level
        risk_level = "critical" if (public_read or public_write) else "medium" if public_list else "low"
        
        # Generate recommendations
        recommendations = self._generate_recommendations(public_read, public_write, public_list, policy_public)
        
        return S3BucketRisk(
            name=bucket_name,
            region=self._get_bucket_region(bucket_name),
            public_read=public_read or policy_public,
            public_write=public_write,
            public_list=public_list,
            anonymous_access=public_read or public_write or public_list,
            risk_level=risk_level,
            recommendations=recommendations
        )
    
    def _check_public_read(self, acl):
        for grant in acl['Grants']:
            if 'AllUsers' in str(grant.get('Grantee', {})) and 'READ' in str(grant):
                return True
        return False
    
    def _check_public_write(self, acl):
        for grant in acl['Grants']:
            if 'AllUsers' in str(grant.get('Grantee', {})) and 'WRITE' in str(grant):
                return True
        return False
    
    def _check_public_list(self, acl):
        for grant in acl['Grants']:
            if 'AllUsers' in str(grant.get('Grantee', {})) and 'READ_ACP' in str(grant):
                return True
        return False
    
    def _check_policy_public(self, policy_str):
        policy = json.loads(policy_str)
        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                if principal == '*' or 'AWS' in principal and '*' in principal['AWS']:
                    return True
        return False
    
    def _get_bucket_region(self, bucket_name):
        try:
            return self.s3.get_bucket_location(Bucket=bucket_name)['LocationConstraint'] or 'us-east-1'
        except:
            return 'unknown'
    
    def _generate_recommendations(self, public_read, public_write, public_list, policy_public):
        recommendations = []
        
        if public_read:
            recommendations.append("Disable public read access - restrict to specific IAM principals")
        if public_write:
            recommendations.append("CRITICAL: Disable public write access immediately")
        if public_list:
            recommendations.append("Disable public list access to prevent bucket enumeration")
        if policy_public:
            recommendations.append("Review and restrict bucket policy - remove wildcard principals")
        
        recommendations.extend([
            "Enable S3 Block Public Access at account level",
            "Enable S3 server-side encryption",
            "Enable S3 access logging",
            "Review IAM policies with S3 permissions"
        ])
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='Detect public S3 buckets')
    parser.add_argument('--output', default='s3_public_buckets.json')
    
    args = parser.parse_args()
    
    try:
        detector = S3PublicDetector()
        risks = detector.detect_public_buckets()
        
        # Filter for risky buckets
        risky_buckets = [r for r in risks if r.anonymous_access]
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_buckets": len(risks),
            "public_buckets": len(risky_buckets),
            "risks": [asdict(r) for r in risky_buckets]
        }
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Found {len(risky_buckets)} public buckets out of {len(risks)} total")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
