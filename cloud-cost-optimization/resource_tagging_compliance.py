#!/usr/bin/env python3
"""
Resource Tagging Compliance Checker
Author: CloudOps-SRE-Toolkit
Description: Check cloud resources for tagging compliance across multiple providers
"""

import os
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Any, Set, Optional
import boto3
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.costmanagement import CostManagementClient
import pandas as pd
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'tagging_compliance_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    ERROR = "ERROR"

@dataclass
class TaggingRule:
    """Represents a tagging compliance rule"""
    name: str
    required_tags: List[str]
    optional_tags: List[str] = None
    tag_format_rules: Dict[str, str] = None  # tag_name: regex_pattern
    case_sensitive: bool = True
    
    def __post_init__(self):
        if self.optional_tags is None:
            self.optional_tags = []
        if self.tag_format_rules is None:
            self.tag_format_rules = {}

@dataclass
class ResourceComplianceResult:
    """Represents compliance result for a single resource"""
    resource_id: str
    resource_type: str
    resource_name: str
    provider: str
    region: str
    compliance_status: ComplianceStatus
    missing_tags: List[str]
    invalid_tags: List[str]
    all_tags: Dict[str, str]
    rule_name: str

class TaggingComplianceChecker:
    """Main class for checking tagging compliance across cloud providers"""
    
    def __init__(self, config_file: str = "config/tagging_config.json"):
        self.config = self._load_config(config_file)
        self.rules = self._load_rules()
        self.results: List[ResourceComplianceResult] = []
        
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
            "aws": {
                "regions": ["us-east-1", "us-west-2", "eu-west-1"],
                "resource_types": [
                    "ec2:instance",
                    "ec2:volume", 
                    "rds:db",
                    "s3:bucket",
                    "lambda:function"
                ]
            },
            "azure": {
                "subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID"),
                "resource_types": [
                    "Microsoft.Compute/virtualMachines",
                    "Microsoft.Storage/storageAccounts",
                    "Microsoft.Sql/servers",
                    "Microsoft.Web/sites"
                ]
            },
            "gcp": {
                "project_id": os.getenv("GCP_PROJECT_ID"),
                "resource_types": [
                    "compute.googleapis.com/Instance",
                    "storage.googleapis.com/Bucket",
                    "sqladmin.googleapis.com/Instance"
                ]
            },
            "output": {
                "format": ["json", "csv", "html"],
                "include_recommendations": True
            }
        }
    
    def _load_rules(self) -> List[TaggingRule]:
        """Load tagging rules from configuration"""
        rules_config = self.config.get("tagging_rules", [])
        rules = []
        
        for rule_config in rules_config:
            rule = TaggingRule(
                name=rule_config["name"],
                required_tags=rule_config["required_tags"],
                optional_tags=rule_config.get("optional_tags", []),
                tag_format_rules=rule_config.get("tag_format_rules", {}),
                case_sensitive=rule_config.get("case_sensitive", True)
            )
            rules.append(rule)
        
        # Add default rule if none specified
        if not rules:
            default_rule = TaggingRule(
                name="default",
                required_tags=["Environment", "Owner", "Project", "CostCenter"],
                optional_tags=["Backup", "TTL", "ManagedBy"],
                tag_format_rules={
                    "Environment": "^(prod|staging|dev|test)$",
                    "CostCenter": "^CC-\\d{4}$"
                }
            )
            rules.append(default_rule)
        
        logger.info(f"Loaded {len(rules)} tagging rules")
        return rules
    
    def check_aws_compliance(self) -> List[ResourceComplianceResult]:
        """Check AWS resource tagging compliance"""
        logger.info("Checking AWS resource tagging compliance...")
        results = []
        
        try:
            for region in self.config["aws"]["regions"]:
                logger.info(f"Checking AWS region: {region}")
                
                # Check EC2 instances
                results.extend(self._check_aws_ec2_instances(region))
                
                # Check EBS volumes
                results.extend(self._check_aws_ebs_volumes(region))
                
                # Check RDS instances
                results.extend(self._check_aws_rds_instances(region))
                
                # Check S3 buckets (global)
                if region == self.config["aws"]["regions"][0]:
                    results.extend(self._check_aws_s3_buckets())
                
                # Check Lambda functions
                results.extend(self._check_aws_lambda_functions(region))
        
        except Exception as e:
            logger.error(f"Error checking AWS compliance: {str(e)}")
        
        return results
    
    def _check_aws_ec2_instances(self, region: str) -> List[ResourceComplianceResult]:
        """Check EC2 instance tagging"""
        results = []
        
        try:
            ec2 = boto3.client('ec2', region_name=region)
            response = ec2.describe_instances()
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    
                    # Get instance name from tags
                    instance_name = tags.get('Name', instance_id)
                    
                    # Check compliance against all rules
                    for rule in self.rules:
                        compliance_result = self._check_resource_compliance(
                            resource_id=instance_id,
                            resource_type="ec2:instance",
                            resource_name=instance_name,
                            provider="AWS",
                            region=region,
                            tags=tags,
                            rule=rule
                        )
                        results.append(compliance_result)
        
        except Exception as e:
            logger.error(f"Error checking EC2 instances in {region}: {str(e)}")
        
        return results
    
    def _check_aws_ebs_volumes(self, region: str) -> List[ResourceComplianceResult]:
        """Check EBS volume tagging"""
        results = []
        
        try:
            ec2 = boto3.client('ec2', region_name=region)
            response = ec2.describe_volumes()
            
            for volume in response['Volumes']:
                volume_id = volume['VolumeId']
                tags = {tag['Key']: tag['Value'] for tag in volume.get('Tags', [])}
                volume_name = tags.get('Name', volume_id)
                
                for rule in self.rules:
                    compliance_result = self._check_resource_compliance(
                        resource_id=volume_id,
                        resource_type="ec2:volume",
                        resource_name=volume_name,
                        provider="AWS",
                        region=region,
                        tags=tags,
                        rule=rule
                    )
                    results.append(compliance_result)
        
        except Exception as e:
            logger.error(f"Error checking EBS volumes in {region}: {str(e)}")
        
        return results
    
    def _check_aws_rds_instances(self, region: str) -> List[ResourceComplianceResult]:
        """Check RDS instance tagging"""
        results = []
        
        try:
            rds = boto3.client('rds', region_name=region)
            response = rds.describe_db_instances()
            
            for db_instance in response['DBInstances']:
                db_id = db_instance['DBInstanceIdentifier']
                tags = {tag['Key']: tag['Value'] for tag in 
                       rds.list_tags_for_resource(ResourceName=db_instance['DBInstanceArn'])['TagList']}
                
                for rule in self.rules:
                    compliance_result = self._check_resource_compliance(
                        resource_id=db_id,
                        resource_type="rds:db",
                        resource_name=db_id,
                        provider="AWS",
                        region=region,
                        tags=tags,
                        rule=rule
                    )
                    results.append(compliance_result)
        
        except Exception as e:
            logger.error(f"Error checking RDS instances in {region}: {str(e)}")
        
        return results
    
    def _check_aws_s3_buckets(self) -> List[ResourceComplianceResult]:
        """Check S3 bucket tagging"""
        results = []
        
        try:
            s3 = boto3.client('s3')
            response = s3.list_buckets()
            
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                
                try:
                    tags = {tag['Key']: tag['Value'] for tag in 
                           s3.get_bucket_tagging(Bucket=bucket_name)['TagSet']}
                except s3.exceptions.NoSuchTagSet:
                    tags = {}
                
                for rule in self.rules:
                    compliance_result = self._check_resource_compliance(
                        resource_id=bucket_name,
                        resource_type="s3:bucket",
                        resource_name=bucket_name,
                        provider="AWS",
                        region="global",
                        tags=tags,
                        rule=rule
                    )
                    results.append(compliance_result)
        
        except Exception as e:
            logger.error(f"Error checking S3 buckets: {str(e)}")
        
        return results
    
    def _check_aws_lambda_functions(self, region: str) -> List[ResourceComplianceResult]:
        """Check Lambda function tagging"""
        results = []
        
        try:
            lambda_client = boto3.client('lambda', region_name=region)
            response = lambda_client.list_functions()
            
            for function in response['Functions']:
                function_name = function['FunctionName']
                function_arn = function['FunctionArn']
                
                try:
                    tags = lambda_client.list_tags(Resource=function_arn)['Tags']
                except Exception:
                    tags = {}
                
                for rule in self.rules:
                    compliance_result = self._check_resource_compliance(
                        resource_id=function_arn,
                        resource_type="lambda:function",
                        resource_name=function_name,
                        provider="AWS",
                        region=region,
                        tags=tags,
                        rule=rule
                    )
                    results.append(compliance_result)
        
        except Exception as e:
            logger.error(f"Error checking Lambda functions in {region}: {str(e)}")
        
        return results
    
    def check_azure_compliance(self) -> List[ResourceComplianceResult]:
        """Check Azure resource tagging compliance"""
        logger.info("Checking Azure resource tagging compliance...")
        results = []
        
        try:
            credential = DefaultAzureCredential()
            resource_client = ResourceManagementClient(
                credential, 
                self.config["azure"]["subscription_id"]
            )
            
            # Get all resources
            resources = resource_client.resources.list()
            
            for resource in resources:
                resource_id = str(resource.id)
                resource_type = str(resource.type)
                resource_name = resource.name
                tags = resource.tags or {}
                
                # Extract region from resource ID
                region = resource.location or "global"
                
                for rule in self.rules:
                    compliance_result = self._check_resource_compliance(
                        resource_id=resource_id,
                        resource_type=resource_type,
                        resource_name=resource_name,
                        provider="Azure",
                        region=region,
                        tags=tags,
                        rule=rule
                    )
                    results.append(compliance_result)
        
        except Exception as e:
            logger.error(f"Error checking Azure compliance: {str(e)}")
        
        return results
    
    def _check_resource_compliance(self, resource_id: str, resource_type: str, 
                                 resource_name: str, provider: str, region: str,
                                 tags: Dict[str, str], rule: TaggingRule) -> ResourceComplianceResult:
        """Check if a resource complies with tagging rules"""
        
        missing_tags = []
        invalid_tags = []
        
        # Check required tags
        for required_tag in rule.required_tags:
            if required_tag not in tags:
                missing_tags.append(required_tag)
        
        # Check tag format rules
        for tag_name, pattern in rule.tag_format_rules.items():
            if tag_name in tags:
                import re
                if not re.match(pattern, tags[tag_name]):
                    invalid_tags.append(f"{tag_name}: '{tags[tag_name]}' (pattern: {pattern})")
        
        # Determine compliance status
        if not missing_tags and not invalid_tags:
            compliance_status = ComplianceStatus.COMPLIANT
        elif missing_tags and not invalid_tags:
            compliance_status = ComplianceStatus.NON_COMPLIANT
        else:
            compliance_status = ComplianceStatus.PARTIALLY_COMPLIANT
        
        return ResourceComplianceResult(
            resource_id=resource_id,
            resource_type=resource_type,
            resource_name=resource_name,
            provider=provider,
            region=region,
            compliance_status=compliance_status,
            missing_tags=missing_tags,
            invalid_tags=invalid_tags,
            all_tags=tags,
            rule_name=rule.name
        )
    
    def run_compliance_check(self) -> List[ResourceComplianceResult]:
        """Run compliance check across all configured providers"""
        logger.info("Starting tagging compliance check...")
        
        all_results = []
        
        # Check AWS compliance
        if "aws" in self.config:
            all_results.extend(self.check_aws_compliance())
        
        # Check Azure compliance
        if "azure" in self.config:
            all_results.extend(self.check_azure_compliance())
        
        # Check GCP compliance (placeholder for future implementation)
        if "gcp" in self.config:
            logger.info("GCP compliance check not yet implemented")
        
        self.results = all_results
        logger.info(f"Compliance check completed. Analyzed {len(all_results)} resources.")
        
        return all_results
    
    def generate_report(self, output_format: List[str]) -> None:
        """Generate compliance report"""
        if not self.results:
            logger.warning("No compliance results to report")
            return
        
        if 'json' in output_format:
            self._generate_json_report()
        
        if 'csv' in output_format:
            self._generate_csv_report()
        
        if 'html' in output_format:
            self._generate_html_report()
    
    def _generate_json_report(self) -> None:
        """Generate JSON compliance report"""
        # Convert results to dict for JSON serialization
        results_dict = []
        for result in self.results:
            results_dict.append({
                'resource_id': result.resource_id,
                'resource_type': result.resource_type,
                'resource_name': result.resource_name,
                'provider': result.provider,
                'region': result.region,
                'compliance_status': result.compliance_status.value,
                'missing_tags': result.missing_tags,
                'invalid_tags': result.invalid_tags,
                'all_tags': result.all_tags,
                'rule_name': result.rule_name
            })
        
        # Generate summary statistics
        total_resources = len(self.results)
        compliant_count = sum(1 for r in self.results if r.compliance_status == ComplianceStatus.COMPLIANT)
        non_compliant_count = sum(1 for r in self.results if r.compliance_status == ComplianceStatus.NON_COMPLIANT)
        partially_compliant_count = sum(1 for r in self.results if r.compliance_status == ComplianceStatus.PARTIALLY_COMPLIANT)
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_resources': total_resources,
                'compliant': compliant_count,
                'non_compliant': non_compliant_count,
                'partially_compliant': partially_compliant_count,
                'compliance_percentage': round((compliant_count / total_resources) * 100, 2) if total_resources > 0 else 0
            },
            'by_provider': self._get_provider_summary(),
            'by_region': self._get_region_summary(),
            'by_resource_type': self._get_resource_type_summary(),
            'missing_tags_summary': self._get_missing_tags_summary(),
            'detailed_results': results_dict
        }
        
        output_file = f"tagging_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"JSON report saved to: {output_file}")
    
    def _generate_csv_report(self) -> None:
        """Generate CSV compliance report"""
        df = pd.DataFrame([
            {
                'Resource ID': result.resource_id,
                'Resource Name': result.resource_name,
                'Resource Type': result.resource_type,
                'Provider': result.provider,
                'Region': result.region,
                'Compliance Status': result.compliance_status.value,
                'Missing Tags': ', '.join(result.missing_tags),
                'Invalid Tags': ', '.join(result.invalid_tags),
                'Rule Name': result.rule_name,
                'Total Tags': len(result.all_tags)
            }
            for result in self.results
        ])
        
        output_file = f"tagging_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(output_file, index=False)
        logger.info(f"CSV report saved to: {output_file}")
    
    def _generate_html_report(self) -> None:
        """Generate HTML compliance report"""
        html_content = self._create_html_report()
        
        output_file = f"tagging_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to: {output_file}")
    
    def _create_html_report(self) -> str:
        """Create HTML report content"""
        # Calculate summary statistics
        total_resources = len(self.results)
        compliant_count = sum(1 for r in self.results if r.compliance_status == ComplianceStatus.COMPLIANT)
        non_compliant_count = sum(1 for r in self.results if r.compliance_status == ComplianceStatus.NON_COMPLIANT)
        partially_compliant_count = sum(1 for r in self.results if r.compliance_status == ComplianceStatus.PARTIALLY_COMPLIANT)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Tagging Compliance Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .summary-item {{ text-align: center; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .compliant {{ background-color: #d4edda; }}
                .non-compliant {{ background-color: #f8d7da; }}
                .partially-compliant {{ background-color: #fff3cd; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .status-compliant {{ color: green; font-weight: bold; }}
                .status-non-compliant {{ color: red; font-weight: bold; }}
                .status-partially-compliant {{ color: orange; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Tagging Compliance Report</h1>
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <div class="summary-item">
                    <h3>{total_resources}</h3>
                    <p>Total Resources</p>
                </div>
                <div class="summary-item compliant">
                    <h3>{compliant_count}</h3>
                    <p>Compliant</p>
                </div>
                <div class="summary-item non-compliant">
                    <h3>{non_compliant_count}</h3>
                    <p>Non-Compliant</p>
                </div>
                <div class="summary-item partially-compliant">
                    <h3>{partially_compliant_count}</h3>
                    <p>Partially Compliant</p>
                </div>
            </div>
            
            <h2>Detailed Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Resource Name</th>
                        <th>Resource Type</th>
                        <th>Provider</th>
                        <th>Region</th>
                        <th>Compliance Status</th>
                        <th>Missing Tags</th>
                        <th>Invalid Tags</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for result in self.results:
            status_class = f"status-{result.compliance_status.value.lower().replace('_', '-')}"
            missing_tags = ', '.join(result.missing_tags) if result.missing_tags else 'None'
            invalid_tags = ', '.join(result.invalid_tags) if result.invalid_tags else 'None'
            
            html += f"""
                    <tr>
                        <td>{result.resource_name}</td>
                        <td>{result.resource_type}</td>
                        <td>{result.provider}</td>
                        <td>{result.region}</td>
                        <td class="{status_class}">{result.compliance_status.value}</td>
                        <td>{missing_tags}</td>
                        <td>{invalid_tags}</td>
                    </tr>
            """
        
        html += """
                </tbody>
            </table>
        </body>
        </html>
        """
        
        return html
    
    def _get_provider_summary(self) -> Dict[str, Any]:
        """Get compliance summary by provider"""
        summary = {}
        for result in self.results:
            provider = result.provider
            if provider not in summary:
                summary[provider] = {
                    'total': 0,
                    'compliant': 0,
                    'non_compliant': 0,
                    'partially_compliant': 0
                }
            
            summary[provider]['total'] += 1
            if result.compliance_status == ComplianceStatus.COMPLIANT:
                summary[provider]['compliant'] += 1
            elif result.compliance_status == ComplianceStatus.NON_COMPLIANT:
                summary[provider]['non_compliant'] += 1
            else:
                summary[provider]['partially_compliant'] += 1
        
        return summary
    
    def _get_region_summary(self) -> Dict[str, Any]:
        """Get compliance summary by region"""
        summary = {}
        for result in self.results:
            region = result.region
            if region not in summary:
                summary[region] = {
                    'total': 0,
                    'compliant': 0,
                    'non_compliant': 0,
                    'partially_compliant': 0
                }
            
            summary[region]['total'] += 1
            if result.compliance_status == ComplianceStatus.COMPLIANT:
                summary[region]['compliant'] += 1
            elif result.compliance_status == ComplianceStatus.NON_COMPLIANT:
                summary[region]['non_compliant'] += 1
            else:
                summary[region]['partially_compliant'] += 1
        
        return summary
    
    def _get_resource_type_summary(self) -> Dict[str, Any]:
        """Get compliance summary by resource type"""
        summary = {}
        for result in self.results:
            resource_type = result.resource_type
            if resource_type not in summary:
                summary[resource_type] = {
                    'total': 0,
                    'compliant': 0,
                    'non_compliant': 0,
                    'partially_compliant': 0
                }
            
            summary[resource_type]['total'] += 1
            if result.compliance_status == ComplianceStatus.COMPLIANT:
                summary[resource_type]['compliant'] += 1
            elif result.compliance_status == ComplianceStatus.NON_COMPLIANT:
                summary[resource_type]['non_compliant'] += 1
            else:
                summary[resource_type]['partially_compliant'] += 1
        
        return summary
    
    def _get_missing_tags_summary(self) -> Dict[str, int]:
        """Get summary of most frequently missing tags"""
        missing_tags_count = {}
        for result in self.results:
            for missing_tag in result.missing_tags:
                missing_tags_count[missing_tag] = missing_tags_count.get(missing_tag, 0) + 1
        
        return dict(sorted(missing_tags_count.items(), key=lambda x: x[1], reverse=True))

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Check resource tagging compliance')
    parser.add_argument('--config', type=str, default='config/tagging_config.json', 
                       help='Configuration file path')
    parser.add_argument('--output-format', nargs='+', default=['json', 'csv', 'html'], 
                       choices=['json', 'csv', 'html'], help='Output formats')
    
    args = parser.parse_args()
    
    try:
        checker = TaggingComplianceChecker(args.config)
        logger.info("Starting tagging compliance check...")
        
        results = checker.run_compliance_check()
        checker.generate_report(args.output_format)
        
        # Print summary to console
        total_resources = len(results)
        compliant_count = sum(1 for r in results if r.compliance_status == ComplianceStatus.COMPLIANT)
        compliance_percentage = round((compliant_count / total_resources) * 100, 2) if total_resources > 0 else 0
        
        print(f"\n=== Compliance Summary ===")
        print(f"Total Resources: {total_resources}")
        print(f"Compliant: {compliant_count} ({compliance_percentage}%)")
        print(f"Non-Compliant: {sum(1 for r in results if r.compliance_status == ComplianceStatus.NON_COMPLIANT)}")
        print(f"Partially Compliant: {sum(1 for r in results if r.compliance_status == ComplianceStatus.PARTIALLY_COMPLIANT)}")
        
        logger.info("Tagging compliance check completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during compliance check: {str(e)}")
        raise

if __name__ == "__main__":
    main()
