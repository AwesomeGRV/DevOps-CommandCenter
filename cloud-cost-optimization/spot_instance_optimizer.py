#!/usr/bin/env python3
"""
Spot Instance Optimizer
Author: DevOps-CommandCenter
Description: Optimize spot instance usage for cost savings with reliability considerations
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
class SpotRecommendation:
    instance_type: str
    current_on_demand_price: float
    spot_price: float
    savings_percentage: float
    interruption_rate: float
    reliability_score: float
    recommended_capacity: int
    backup_strategy: str
    regions: List[str]

class SpotInstanceOptimizer:
    def __init__(self):
        self.ec2 = boto3.client('ec2')
        self.pricing = boto3.client('pricing')
        self.cloudwatch = boto3.client('cloudwatch')
    
    def optimize_spot_instances(self, workload_type: str = 'flexible') -> List[SpotRecommendation]:
        """Analyze and optimize spot instance usage"""
        recommendations = []
        
        # Get current instances
        instances = self._get_current_instances()
        
        # Analyze each instance for spot suitability
        for instance in instances:
            try:
                recommendation = self._analyze_spot_suitability(instance, workload_type)
                if recommendation:
                    recommendations.append(recommendation)
            except Exception as e:
                logger.error(f"Error analyzing instance {instance['InstanceId']}: {str(e)}")
        
        return sorted(recommendations, key=lambda x: x.savings_percentage, reverse=True)
    
    def _get_current_instances(self) -> List[Dict]:
        """Get current running instances"""
        instances = []
        
        try:
            response = self.ec2.describe_instances(Filters=[
                {'Name': 'instance-state-name', 'Values': ['running']}
            ])
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append(instance)
        
        except Exception as e:
            logger.error(f"Error getting instances: {str(e)}")
        
        return instances
    
    def _analyze_spot_suitability(self, instance: Dict, workload_type: str) -> Optional[SpotRecommendation]:
        """Analyze if an instance is suitable for spot"""
        instance_type = instance['InstanceType']
        region = instance['Placement']['AvailabilityZone'][:-1]
        
        # Get pricing information
        on_demand_price = self._get_on_demand_price(instance_type, region)
        spot_prices = self._get_spot_prices(instance_type, region)
        
        if not spot_prices:
            return None
        
        # Calculate average spot price and savings
        avg_spot_price = sum(spot_prices) / len(spot_prices)
        savings_percentage = ((on_demand_price - avg_spot_price) / on_demand_price) * 100
        
        # Analyze interruption patterns
        interruption_rate = self._calculate_interruption_rate(instance_type, region)
        
        # Calculate reliability score
        reliability_score = self._calculate_reliability_score(
            interruption_rate, workload_type, len(spot_prices)
        )
        
        # Determine backup strategy
        backup_strategy = self._recommend_backup_strategy(workload_type, reliability_score)
        
        # Get alternative regions
        alternative_regions = self._get_alternative_regions(instance_type)
        
        return SpotRecommendation(
            instance_type=instance_type,
            current_on_demand_price=on_demand_price,
            spot_price=avg_spot_price,
            savings_percentage=savings_percentage,
            interruption_rate=interruption_rate,
            reliability_score=reliability_score,
            recommended_capacity=1,  # Would be calculated based on workload
            backup_strategy=backup_strategy,
            regions=alternative_regions
        )
    
    def _get_on_demand_price(self, instance_type: str, region: str) -> float:
        """Get on-demand price for instance type"""
        try:
            response = self.pricing.get_products(
                ServiceCode='AmazonEC2',
                Filters=[
                    {'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_type},
                    {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': self._get_region_name(region)},
                    {'Type': 'TERM_MATCH', 'Field': 'tenancy', 'Value': 'Shared'},
                    {'Type': 'TERM_MATCH', 'Field': 'operatingSystem', 'Value': 'Linux'},
                    {'Type': 'TERM_MATCH', 'Field': 'capacitystatus', 'Value': 'Used'}
                ]
            )
            
            if response['PriceList']:
                price_data = json.loads(response['PriceList'][0])
                terms = price_data['terms']['OnDemand']
                for term in terms.values():
                    for dimension in term['priceDimensions'].values():
                        return float(dimension['pricePerUnit']['USD'])
        
        except Exception as e:
            logger.warning(f"Could not get on-demand price for {instance_type}: {str(e)}")
        
        # Fallback pricing
        fallback_prices = {
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
        
        return fallback_prices.get(instance_type, 0.1)
    
    def _get_spot_prices(self, instance_type: str, region: str) -> List[float]:
        """Get historical spot prices"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=7)
            
            response = self.ec2.describe_spot_price_history(
                InstanceTypes=[instance_type],
                ProductDescriptions=['Linux/UNIX'],
                StartTime=start_time,
                EndTime=end_time,
                AvailabilityZone=f"{region}a"
            )
            
            return [float(spot['SpotPrice']) for spot in response['SpotPriceHistory']]
        
        except Exception as e:
            logger.warning(f"Could not get spot prices for {instance_type}: {str(e)}")
            return []
    
    def _calculate_interruption_rate(self, instance_type: str, region: str) -> float:
        """Calculate historical interruption rate"""
        # Simplified calculation - in practice, use more sophisticated analysis
        try:
            # Get spot price volatility as proxy for interruption risk
            spot_prices = self._get_spot_prices(instance_type, region)
            
            if len(spot_prices) < 2:
                return 0.5  # Default medium risk
            
            # Calculate price volatility
            price_changes = []
            for i in range(1, len(spot_prices)):
                change = abs(spot_prices[i] - spot_prices[i-1]) / spot_prices[i-1]
                price_changes.append(change)
            
            avg_volatility = sum(price_changes) / len(price_changes)
            
            # Map volatility to interruption rate
            if avg_volatility > 0.5:
                return 0.8  # High interruption risk
            elif avg_volatility > 0.2:
                return 0.5  # Medium interruption risk
            else:
                return 0.2  # Low interruption risk
        
        except Exception:
            return 0.5  # Default medium risk
    
    def _calculate_reliability_score(self, interruption_rate: float, 
                                   workload_type: str, data_points: int) -> float:
        """Calculate reliability score for spot usage"""
        base_score = 1.0 - interruption_rate
        
        # Adjust based on workload type
        workload_multipliers = {
            'flexible': 1.0,      # Batch processing, CI/CD
            'stateless': 0.8,      # Web servers, APIs
            'stateful': 0.4,       # Databases, storage
            'critical': 0.2        # Production critical
        }
        
        multiplier = workload_multipliers.get(workload_type, 0.5)
        
        # Adjust based on data availability
        data_confidence = min(data_points / 100, 1.0) * 0.2
        
        return min(base_score * multiplier + data_confidence, 1.0)
    
    def _recommend_backup_strategy(self, workload_type: str, reliability_score: float) -> str:
        """Recommend backup strategy for spot instances"""
        if reliability_score < 0.3:
            return "hybrid_mixed"  # Mix of on-demand and spot
        elif reliability_score < 0.6:
            return "hybrid_spot_primary"  # Spot primary with on-demand backup
        else:
            return "spot_only"  # Spot only with checkpointing
    
    def _get_alternative_regions(self, instance_type: str) -> List[str]:
        """Get alternative regions with good spot availability"""
        # Simplified - in practice, check actual availability
        regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
        
        # Randomly select a few for demonstration
        import random
        return random.sample(regions, min(3, len(regions)))
    
    def _get_region_name(self, region_code: str) -> str:
        """Convert region code to full name"""
        region_names = {
            'us-east-1': 'US East (N. Virginia)',
            'us-west-2': 'US West (Oregon)',
            'eu-west-1': 'EU (Ireland)',
            'ap-southeast-1': 'Asia Pacific (Singapore)'
        }
        
        return region_names.get(region_code, region_code)
    
    def generate_spot_fleet_config(self, recommendations: List[SpotRecommendation], 
                                 workload_type: str) -> Dict[str, Any]:
        """Generate spot fleet configuration"""
        # Select best recommendations
        best_recommendations = [r for r in recommendations if r.reliability_score > 0.4][:5]
        
        if not best_recommendations:
            return {"error": "No suitable spot instances found"}
        
        # Create spot fleet configuration
        fleet_config = {
            "SpotFleetRequestConfig": {
                "SpotPrice": "",
                "TargetCapacity": 10,
                "IamFleetRole": "arn:aws:iam::123456789012:role/aws-ec2-spot-fleet-role",
                "AllocationStrategy": "diversified",
                "LaunchSpecifications": []
            }
        }
        
        for rec in best_recommendations:
            launch_spec = {
                "ImageId": "ami-12345678",  # Would be determined based on region
                "InstanceType": rec.instance_type,
                "SubnetId": "subnet-12345678",
                "WeightedCapacity": 1,
                "TagSpecifications": [
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "Name", "Value": f"spot-{rec.instance_type}"},
                            {"Key": "Workload", "Value": workload_type},
                            {"Key": "ManagedBy", "Value": "DevOps-CommandCenter"}
                        ]
                    }
                ]
            }
            
            fleet_config["SpotFleetRequestConfig"]["LaunchSpecifications"].append(launch_spec)
        
        return fleet_config
    
    def generate_report(self, recommendations: List[SpotRecommendation], 
                       workload_type: str) -> Dict[str, Any]:
        """Generate spot optimization report"""
        total_potential_savings = sum(r.savings_percentage for r in recommendations)
        avg_reliability = sum(r.reliability_score for r in recommendations) / len(recommendations) if recommendations else 0
        
        # Group by reliability
        high_reliability = [r for r in recommendations if r.reliability_score > 0.7]
        medium_reliability = [r for r in recommendations if 0.4 <= r.reliability_score <= 0.7]
        low_reliability = [r for r in recommendations if r.reliability_score < 0.4]
        
        return {
            "timestamp": datetime.now().isoformat(),
            "workload_type": workload_type,
            "summary": {
                "total_recommendations": len(recommendations),
                "average_savings_percentage": total_potential_savings / len(recommendations) if recommendations else 0,
                "average_reliability_score": avg_reliability,
                "high_reliability_count": len(high_reliability),
                "medium_reliability_count": len(medium_reliability),
                "low_reliability_count": len(low_reliability)
            },
            "recommendations": [asdict(r) for r in recommendations],
            "spot_fleet_config": self.generate_spot_fleet_config(recommendations, workload_type),
            "implementation_plan": self._generate_implementation_plan(recommendations, workload_type)
        }
    
    def _generate_implementation_plan(self, recommendations: List[SpotRecommendation], 
                                  workload_type: str) -> List[str]:
        """Generate implementation plan"""
        plan = []
        
        high_reliability = [r for r in recommendations if r.reliability_score > 0.7]
        
        if high_reliability:
            plan.append(f"Phase 1: Implement {len(high_reliability)} high-reliability spot instances")
            plan.append("  - Set up spot fleet with diversified allocation")
            plan.append("  - Configure automatic scaling and health checks")
            plan.append("  - Implement checkpointing for state preservation")
        
        medium_reliability = [r for r in recommendations if 0.4 <= r.reliability_score <= 0.7]
        
        if medium_reliability:
            plan.append(f"Phase 2: Implement {len(medium_reliability)} medium-reliability spot instances")
            plan.append("  - Use hybrid approach with on-demand backup")
            plan.append("  - Configure capacity rebalancing")
            plan.append("  - Set up monitoring for interruption notices")
        
        plan.extend([
            "Phase 3: Monitor and optimize",
            "  - Track cost savings and reliability metrics",
            "  - Adjust allocation based on actual performance",
            "  - Implement automated failover mechanisms"
        ])
        
        return plan

def main():
    parser = argparse.ArgumentParser(description='Optimize spot instance usage')
    parser.add_argument('--workload-type', choices=['flexible', 'stateless', 'stateful', 'critical'], 
                       default='flexible', help='Type of workload')
    parser.add_argument('--output', default='spot_optimization_report.json')
    parser.add_argument('--min-savings', type=float, default=20.0, help='Minimum savings percentage')
    
    args = parser.parse_args()
    
    try:
        optimizer = SpotInstanceOptimizer()
        recommendations = optimizer.optimize_spot_instances(args.workload_type)
        
        # Filter by minimum savings
        filtered_recommendations = [r for r in recommendations if r.savings_percentage >= args.min_savings]
        
        report = optimizer.generate_report(filtered_recommendations, args.workload_type)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Spot Instance Optimization Summary:")
        print(f"Total recommendations: {report['summary']['total_recommendations']}")
        print(f"Average savings: {report['summary']['average_savings_percentage']:.1f}%")
        print(f"Average reliability: {report['summary']['average_reliability_score']:.2f}")
        print(f"High reliability options: {report['summary']['high_reliability_count']}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error during spot optimization: {str(e)}")

if __name__ == "__main__":
    main()
