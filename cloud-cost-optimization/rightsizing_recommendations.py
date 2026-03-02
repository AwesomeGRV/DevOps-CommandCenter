#!/usr/bin/env python3
"""
Cloud Resource Rightsizing Recommendations
Author: DevOps-CommandCenter
Description: Analyze cloud resource utilization and provide rightsizing recommendations
"""

import boto3
import json
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ResourceRecommendation:
    resource_id: str
    resource_type: str
    current_size: str
    recommended_size: str
    utilization_cpu: float
    utilization_memory: float
    monthly_savings: float
    confidence_score: float
    recommendation_type: str  # upsize, downsize, terminate

class RightsizingAnalyzer:
    def __init__(self):
        self.ec2 = boto3.client('ec2')
        self.cloudwatch = boto3.client('cloudwatch')
        self.pricing = boto3.client('pricing')
    
    def analyze_ec2_instances(self) -> List[ResourceRecommendation]:
        """Analyze EC2 instances for rightsizing opportunities"""
        recommendations = []
        
        # Get all running instances
        instances = self.ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                try:
                    recommendation = self._analyze_instance(instance)
                    if recommendation:
                        recommendations.append(recommendation)
                except Exception as e:
                    logger.error(f"Error analyzing instance {instance['InstanceId']}: {str(e)}")
        
        return recommendations
    
    def _analyze_instance(self, instance: Dict) -> Optional[ResourceRecommendation]:
        """Analyze a single EC2 instance"""
        instance_id = instance['InstanceId']
        instance_type = instance['InstanceType']
        
        # Get CloudWatch metrics for the last 7 days
        end_time = datetime.now()
        start_time = end_time - timedelta(days=7)
        
        # CPU utilization
        cpu_metrics = self._get_cloudwatch_metric(
            namespace='AWS/EC2',
            metric_name='CPUUtilization',
            dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            start_time=start_time,
            end_time=end_time
        )
        
        # Memory utilization (requires CloudWatch agent)
        memory_metrics = self._get_cloudwatch_metric(
            namespace='CWAgent',
            metric_name='mem_used_percent',
            dimensions=[
                {'Name': 'InstanceId', 'Value': instance_id},
                {'Name': 'objectname', 'Value': 'Memory'}
            ],
            start_time=start_time,
            end_time=end_time
        )
        
        avg_cpu = self._calculate_average(cpu_metrics) if cpu_metrics else 0
        avg_memory = self._calculate_average(memory_metrics) if memory_metrics else 50  # Default if no data
        
        # Get current and recommended instance types
        current_instance = self._get_instance_info(instance_type)
        recommended_type = self._recommend_instance_type(avg_cpu, avg_memory, instance_type)
        
        if recommended_type != instance_type:
            # Calculate potential savings
            current_price = self._get_instance_price(instance_type)
            recommended_price = self._get_instance_price(recommended_type)
            monthly_savings = (current_price - recommended_price) * 730  # 730 hours per month
            
            # Determine recommendation type
            if avg_cpu < 10 and avg_memory < 20:
                rec_type = "terminate"
            elif current_instance['vcpu'] > self._get_instance_info(recommended_type)['vcpu']:
                rec_type = "downsize"
            else:
                rec_type = "upsize"
            
            # Calculate confidence score
            confidence = self._calculate_confidence_score(avg_cpu, avg_memory, len(cpu_metrics))
            
            return ResourceRecommendation(
                resource_id=instance_id,
                resource_type="EC2 Instance",
                current_size=instance_type,
                recommended_size=recommended_type,
                utilization_cpu=avg_cpu,
                utilization_memory=avg_memory,
                monthly_savings=monthly_savings,
                confidence_score=confidence,
                recommendation_type=rec_type
            )
        
        return None
    
    def _get_cloudwatch_metric(self, namespace: str, metric_name: str, 
                             dimensions: List[Dict], start_time: datetime, 
                             end_time: datetime) -> List[float]:
        """Get CloudWatch metrics"""
        try:
            response = self.cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,  # 1 hour
                Statistics=['Average']
            )
            
            return [point['Average'] for point in response['Datapoints']]
        except Exception as e:
            logger.warning(f"Could not get metric {metric_name}: {str(e)}")
            return []
    
    def _calculate_average(self, values: List[float]) -> float:
        """Calculate average of values"""
        return sum(values) / len(values) if values else 0
    
    def _get_instance_info(self, instance_type: str) -> Dict:
        """Get instance type information"""
        # Simplified instance database - in practice, use AWS API
        instance_db = {
            't3.micro': {'vcpu': 2, 'memory': 1},
            't3.small': {'vcpu': 2, 'memory': 2},
            't3.medium': {'vcpu': 2, 'memory': 4},
            't3.large': {'vcpu': 2, 'memory': 8},
            'm5.large': {'vcpu': 2, 'memory': 8},
            'm5.xlarge': {'vcpu': 4, 'memory': 16},
            'm5.2xlarge': {'vcpu': 8, 'memory': 32},
            'c5.large': {'vcpu': 2, 'memory': 4},
            'c5.xlarge': {'vcpu': 4, 'memory': 8},
            'c5.2xlarge': {'vcpu': 8, 'memory': 16},
        }
        
        return instance_db.get(instance_type, {'vcpu': 1, 'memory': 1})
    
    def _recommend_instance_type(self, avg_cpu: float, avg_memory: float, 
                                current_type: str) -> str:
        """Recommend instance type based on utilization"""
        current_info = self._get_instance_info(current_type)
        
        # Rightsizing logic
        if avg_cpu < 20 and avg_memory < 30:
            # Underutilized - recommend smaller instance
            if current_info['vcpu'] >= 8:
                return 'm5.large'
            elif current_info['vcpu'] >= 4:
                return 't3.medium'
            else:
                return 't3.micro'
        elif avg_cpu > 80 or avg_memory > 80:
            # Overutilized - recommend larger instance
            if current_info['vcpu'] <= 2:
                return 'm5.xlarge'
            else:
                return 'm5.2xlarge'
        else:
            # Well-utilized - keep current or similar
            return current_type
    
    def _get_instance_price(self, instance_type: str) -> float:
        """Get hourly price for instance type (simplified)"""
        # Simplified pricing - in practice, use AWS Pricing API
        prices = {
            't3.micro': 0.0104,
            't3.small': 0.0208,
            't3.medium': 0.0416,
            't3.large': 0.0832,
            'm5.large': 0.096,
            'm5.xlarge': 0.192,
            'm5.2xlarge': 0.384,
            'c5.large': 0.085,
            'c5.xlarge': 0.17,
            'c5.2xlarge': 0.34,
        }
        
        return prices.get(instance_type, 0.1)
    
    def _calculate_confidence_score(self, avg_cpu: float, avg_memory: float, 
                                  data_points: int) -> float:
        """Calculate confidence score for recommendation"""
        base_confidence = min(data_points / 168, 1.0) * 0.5  # 50% based on data availability
        
        # Add confidence based on utilization patterns
        if avg_cpu < 10 or avg_cpu > 80:
            utilization_confidence = 0.3  # High confidence for extreme utilization
        elif avg_cpu < 30 or avg_cpu > 70:
            utilization_confidence = 0.2
        else:
            utilization_confidence = 0.1
        
        return min(base_confidence + utilization_confidence, 1.0)
    
    def generate_report(self, recommendations: List[ResourceRecommendation]) -> Dict[str, Any]:
        """Generate rightsizing report"""
        total_savings = sum(r.monthly_savings for r in recommendations)
        
        # Group by recommendation type
        by_type = {}
        for rec in recommendations:
            if rec.recommendation_type not in by_type:
                by_type[rec.recommendation_type] = []
            by_type[rec.recommendation_type].append(rec)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_recommendations": len(recommendations),
            "total_monthly_savings": total_savings,
            "recommendations_by_type": {
                r_type: {
                    "count": len(recs),
                    "savings": sum(r.monthly_savings for r in recs)
                }
                for r_type, recs in by_type.items()
            },
            "recommendations": [asdict(r) for r in recommendations],
            "summary": {
                "high_confidence": len([r for r in recommendations if r.confidence_score > 0.7]),
                "medium_confidence": len([r for r in recommendations if 0.4 <= r.confidence_score <= 0.7]),
                "low_confidence": len([r for r in recommendations if r.confidence_score < 0.4])
            }
        }

def main():
    parser = argparse.ArgumentParser(description='Analyze cloud resources for rightsizing opportunities')
    parser.add_argument('--output', default='rightsizing_report.json')
    parser.add_argument('--min-savings', type=float, default=10.0, help='Minimum monthly savings to include')
    
    args = parser.parse_args()
    
    try:
        analyzer = RightsizingAnalyzer()
        recommendations = analyzer.analyze_ec2_instances()
        
        # Filter by minimum savings
        filtered_recommendations = [r for r in recommendations if r.monthly_savings >= args.min_savings]
        
        report = analyzer.generate_report(filtered_recommendations)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Rightsizing Analysis Summary:")
        print(f"Total recommendations: {report['total_recommendations']}")
        print(f"Potential monthly savings: ${report['total_monthly_savings']:.2f}")
        print(f"High confidence recommendations: {report['summary']['high_confidence']}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error during rightsizing analysis: {str(e)}")

if __name__ == "__main__":
    main()
