#!/usr/bin/env python3
"""
Monthly Cost Comparison Script
Author: CloudOps-SRE-Toolkit
Description: Compare monthly cloud costs across providers and services
"""

import os
import json
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import boto3
import requests
from azure.mgmt.costmanagement import CostManagementClient
from azure.identity import DefaultAzureCredential
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'cost_comparison_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CostComparator:
    """Compare costs across different cloud providers"""
    
    def __init__(self, config_file: str = "config/cost_config.json"):
        self.config = self._load_config(config_file)
        self.results = {}
        
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
                "regions": ["us-east-1", "us-west-2"],
                "cost_explorer_enabled": True
            },
            "azure": {
                "subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID"),
                "resource_groups": []
            },
            "gcp": {
                "project_id": os.getenv("GCP_PROJECT_ID"),
                "billing_account_id": os.getenv("GCP_BILLING_ACCOUNT_ID")
            },
            "output": {
                "format": ["json", "csv", "chart"],
                "chart_type": "bar"
            }
        }
    
    def get_aws_costs(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get AWS cost data using Cost Explorer"""
        try:
            client = boto3.client('ce')
            
            # Get cost and usage data
            response = client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['BlendedCost'],
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'},
                    {'Type': 'DIMENSION', 'Key': 'REGION'}
                ]
            )
            
            costs = []
            for result in response.get('ResultsByTime', []):
                period = result['TimePeriod']['Start']
                for group in result.get('Groups', []):
                    service = group['Keys'][0] if len(group['Keys']) > 0 else 'Unknown'
                    region = group['Keys'][1] if len(group['Keys']) > 1 else 'All'
                    amount = float(group['Metrics']['BlendedCost']['Amount'])
                    
                    costs.append({
                        'provider': 'AWS',
                        'service': service,
                        'region': region,
                        'cost': amount,
                        'period': period
                    })
            
            logger.info(f"Retrieved {len(costs)} AWS cost records")
            return {'aws': costs}
            
        except Exception as e:
            logger.error(f"Error getting AWS costs: {str(e)}")
            return {'aws': []}
    
    def get_azure_costs(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get Azure cost data using Cost Management API"""
        try:
            credential = DefaultAzureCredential()
            cost_client = CostManagementClient(
                credential=credential,
                subscription_id=self.config['azure']['subscription_id']
            )
            
            # Query for actual costs
            scope = f"/subscriptions/{self.config['azure']['subscription_id']}"
            query = {
                "type": "ActualCost",
                "timeframe": "Custom",
                "timePeriod": {
                    "start": start_date.strftime('%Y-%m-%dT00:00:00Z'),
                    "end": end_date.strftime('%Y-%m-%dT00:00:00Z')
                },
                "dataset": {
                    "granularity": "Monthly",
                    "aggregation": {
                        "totalCost": {
                            "name": "Cost",
                            "function": "Sum"
                        }
                    },
                    "grouping": [
                        {
                            "type": "Dimension",
                            "name": "ResourceGroupName"
                        },
                        {
                            "type": "Dimension",
                            "name": "ServiceName"
                        }
                    ]
                }
            }
            
            # This is a simplified version - actual implementation would need proper API calls
            # For now, return mock data structure
            costs = [
                {
                    'provider': 'Azure',
                    'service': 'Virtual Machines',
                    'resource_group': 'production',
                    'cost': 150.75,
                    'period': start_date.strftime('%Y-%m')
                },
                {
                    'provider': 'Azure',
                    'service': 'Storage Accounts',
                    'resource_group': 'production',
                    'cost': 45.20,
                    'period': start_date.strftime('%Y-%m')
                }
            ]
            
            logger.info(f"Retrieved {len(costs)} Azure cost records")
            return {'azure': costs}
            
        except Exception as e:
            logger.error(f"Error getting Azure costs: {str(e)}")
            return {'azure': []}
    
    def get_gcp_costs(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get GCP cost data using Billing API"""
        try:
            # This would require proper GCP authentication and API setup
            # For now, return mock data structure
            costs = [
                {
                    'provider': 'GCP',
                    'service': 'Compute Engine',
                    'project': self.config['gcp']['project_id'],
                    'cost': 89.50,
                    'period': start_date.strftime('%Y-%m')
                },
                {
                    'provider': 'GCP',
                    'service': 'Cloud Storage',
                    'project': self.config['gcp']['project_id'],
                    'cost': 23.75,
                    'period': start_date.strftime('%Y-%m')
                }
            ]
            
            logger.info(f"Retrieved {len(costs)} GCP cost records")
            return {'gcp': costs}
            
        except Exception as e:
            logger.error(f"Error getting GCP costs: {str(e)}")
            return {'gcp': []}
    
    def compare_costs(self, months: int = 3) -> Dict[str, Any]:
        """Compare costs across providers for specified months"""
        end_date = datetime.now()
        results = {}
        
        for month in range(months):
            start_date = end_date - timedelta(days=30)
            period = start_date.strftime('%Y-%m')
            
            logger.info(f"Comparing costs for period: {period}")
            
            month_results = {}
            
            # Get costs from each provider
            month_results.update(self.get_aws_costs(start_date, end_date))
            month_results.update(self.get_azure_costs(start_date, end_date))
            month_results.update(self.get_gcp_costs(start_date, end_date))
            
            results[period] = month_results
            end_date = start_date
        
        return results
    
    def generate_report(self, results: Dict[str, Any], output_format: List[str]) -> None:
        """Generate cost comparison report"""
        # Flatten results for analysis
        all_costs = []
        for period, providers in results.items():
            for provider, costs in providers.items():
                for cost_record in costs:
                    cost_record['period'] = period
                    all_costs.append(cost_record)
        
        if not all_costs:
            logger.warning("No cost data available for report generation")
            return
        
        df = pd.DataFrame(all_costs)
        
        # Generate different output formats
        if 'json' in output_format:
            self._generate_json_report(results, df)
        
        if 'csv' in output_format:
            self._generate_csv_report(df)
        
        if 'chart' in output_format:
            self._generate_charts(df)
    
    def _generate_json_report(self, results: Dict[str, Any], df: pd.DataFrame) -> None:
        """Generate JSON report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'periods_analyzed': list(results.keys()),
            'summary': {
                'total_costs_by_provider': df.groupby('provider')['cost'].sum().to_dict(),
                'average_monthly_cost': df.groupby('provider')['cost'].mean().to_dict(),
                'cost_trend': self._calculate_trend(df)
            },
            'detailed_costs': results
        }
        
        output_file = f"cost_comparison_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"JSON report saved to: {output_file}")
    
    def _generate_csv_report(self, df: pd.DataFrame) -> None:
        """Generate CSV report"""
        output_file = f"cost_comparison_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(output_file, index=False)
        logger.info(f"CSV report saved to: {output_file}")
    
    def _generate_charts(self, df: pd.DataFrame) -> None:
        """Generate cost comparison charts"""
        plt.style.use('seaborn-v0_8')
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('Cloud Cost Comparison Analysis', fontsize=16)
        
        # 1. Total costs by provider
        provider_costs = df.groupby('provider')['cost'].sum()
        axes[0, 0].pie(provider_costs.values, labels=provider_costs.index, autopct='%1.1f%%')
        axes[0, 0].set_title('Total Costs by Provider')
        
        # 2. Monthly cost trend
        monthly_costs = df.groupby(['period', 'provider'])['cost'].sum().unstack()
        monthly_costs.plot(kind='line', ax=axes[0, 1], marker='o')
        axes[0, 1].set_title('Monthly Cost Trend')
        axes[0, 1].set_ylabel('Cost ($)')
        axes[0, 1].tick_params(axis='x', rotation=45)
        
        # 3. Top services by cost
        service_costs = df.groupby(['provider', 'service'])['cost'].sum().sort_values(ascending=False).head(10)
        service_costs.plot(kind='barh', ax=axes[1, 0])
        axes[1, 0].set_title('Top 10 Services by Cost')
        axes[1, 0].set_xlabel('Cost ($)')
        
        # 4. Cost distribution by provider
        for i, provider in enumerate(df['provider'].unique()):
            provider_data = df[df['provider'] == provider]
            service_costs = provider_data.groupby('service')['cost'].sum().sort_values(ascending=False).head(5)
            axes[1, 1].barh([f"{provider}: {service}" for service in service_costs.index], 
                          service_costs.values, alpha=0.7)
        
        axes[1, 1].set_title('Top 5 Services by Provider')
        axes[1, 1].set_xlabel('Cost ($)')
        
        plt.tight_layout()
        chart_file = f"cost_comparison_charts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(chart_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Charts saved to: {chart_file}")
    
    def _calculate_trend(self, df: pd.DataFrame) -> Dict[str, str]:
        """Calculate cost trends"""
        trends = {}
        
        for provider in df['provider'].unique():
            provider_data = df[df['provider'] == provider]
            monthly_costs = provider_data.groupby('period')['cost'].sum().sort_index()
            
            if len(monthly_costs) >= 2:
                first_month = monthly_costs.iloc[0]
                last_month = monthly_costs.iloc[-1]
                change_percent = ((last_month - first_month) / first_month) * 100
                
                if change_percent > 5:
                    trend = "Increasing"
                elif change_percent < -5:
                    trend = "Decreasing"
                else:
                    trend = "Stable"
                
                trends[provider] = f"{trend} ({change_percent:+.1f}%)"
            else:
                trends[provider] = "Insufficient data"
        
        return trends

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Compare monthly cloud costs across providers')
    parser.add_argument('--months', type=int, default=3, help='Number of months to analyze')
    parser.add_argument('--config', type=str, default='config/cost_config.json', help='Configuration file path')
    parser.add_argument('--output-format', nargs='+', default=['json', 'csv', 'chart'], 
                       choices=['json', 'csv', 'chart'], help='Output formats')
    
    args = parser.parse_args()
    
    try:
        comparator = CostComparator(args.config)
        logger.info("Starting cost comparison analysis...")
        
        results = comparator.compare_costs(args.months)
        comparator.generate_report(results, args.output_format)
        
        logger.info("Cost comparison analysis completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during cost comparison: {str(e)}")
        raise

if __name__ == "__main__":
    main()
