#!/usr/bin/env python3
"""
SLA/SLO Calculator
Author: CloudOps-SRE-Toolkit
Description: Calculate and track Service Level Agreements and Service Level Objectives
"""

import os
import json
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'sla_slo_calculation_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class SLAObjective:
    """Data class for SLA objective definition"""
    name: str
    description: str
    metric_type: str  # 'availability', 'latency', 'error_rate', 'throughput'
    target_value: float
    target_unit: str
    time_window_days: int
    alerting_threshold: float  # Alert when approaching SLA breach
    measurement_method: str
    data_source: str
    tags: Dict[str, str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = {}

@dataclass
class SLAMeasurement:
    """Data class for SLA measurement"""
    timestamp: datetime
    objective_name: str
    actual_value: float
    target_value: float
    compliance_percentage: float
    is_compliant: bool
    measurement_period_start: datetime
    measurement_period_end: datetime
    sample_count: int
    additional_data: Dict[str, Any] = None

@dataclass
class SLAReport:
    """Data class for SLA report"""
    timestamp: str
    reporting_period: Dict[str, str]
    objectives_summary: Dict[str, Any]
    overall_compliance: float
    compliance_trend: List[Dict[str, Any]]
    breach_alerts: List[Dict[str, Any]]
    recommendations: List[str]
    detailed_measurements: List[SLAMeasurement]

class SLASLOCalculator:
    """Calculate and track SLA/SLO compliance"""
    
    def __init__(self, config_file: str = "config/sla_slo_config.json"):
        self.config = self._load_config(config_file)
        self.objectives = self._load_objectives()
        self.measurements_history = []
        
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
            "objectives": [
                {
                    "name": "API Availability",
                    "description": "API service availability target",
                    "metric_type": "availability",
                    "target_value": 99.9,
                    "target_unit": "percent",
                    "time_window_days": 30,
                    "alerting_threshold": 99.5,
                    "measurement_method": "uptime_monitoring",
                    "data_source": "synthetic_monitoring",
                    "tags": {"service": "api", "environment": "production"}
                },
                {
                    "name": "API Response Time",
                    "description": "95th percentile response time target",
                    "metric_type": "latency",
                    "target_value": 500,
                    "target_unit": "milliseconds",
                    "time_window_days": 7,
                    "alerting_threshold": 450,
                    "measurement_method": "percentile_calculation",
                    "data_source": "performance_monitoring",
                    "tags": {"service": "api", "environment": "production"}
                },
                {
                    "name": "Error Rate",
                    "description": "Maximum error rate target",
                    "metric_type": "error_rate",
                    "target_value": 0.1,
                    "target_unit": "percent",
                    "time_window_days": 24,
                    "alerting_threshold": 0.05,
                    "measurement_method": "error_counting",
                    "data_source": "log_analysis",
                    "tags": {"service": "api", "environment": "production"}
                }
            ],
            "calculation": {
                "time_periods": ["24h", "7d", "30d"],
                "rolling_window": true,
                "minimum_samples": 100,
                "confidence_level": 0.95
            },
            "alerts": {
                "webhook_url": os.getenv("ALERT_WEBHOOK_URL", ""),
                "slack_webhook": os.getenv("SLACK_WEBHOOK_URL", ""),
                "email_enabled": False,
                "email_recipients": []
            },
            "output": {
                "format": ["json", "csv", "dashboard"],
                "include_trends": True,
                "trend_days": 30
            }
        }
    
    def _load_objectives(self) -> List[SLAObjective]:
        """Load SLA objectives from configuration"""
        objectives = []
        
        for obj_config in self.config.get("objectives", []):
            objective = SLAObjective(
                name=obj_config["name"],
                description=obj_config["description"],
                metric_type=obj_config["metric_type"],
                target_value=obj_config["target_value"],
                target_unit=obj_config["target_unit"],
                time_window_days=obj_config["time_window_days"],
                alerting_threshold=obj_config["alerting_threshold"],
                measurement_method=obj_config["measurement_method"],
                data_source=obj_config["data_source"],
                tags=obj_config.get("tags", {})
            )
            objectives.append(objective)
        
        logger.info(f"Loaded {len(objectives)} SLA objectives")
        return objectives
    
    def calculate_availability_sla(self, objective: SLAObjective, 
                                 start_time: datetime, end_time: datetime) -> SLAMeasurement:
        """Calculate availability SLA"""
        logger.info(f"Calculating availability for {objective.name}")
        
        # Simulate data collection - in real implementation, this would query actual monitoring data
        total_time = (end_time - start_time).total_seconds()
        
        # Generate sample data (replace with actual data collection)
        downtime_events = self._generate_sample_downtime(start_time, end_time, objective.target_value)
        total_downtime = sum(event["duration"] for event in downtime_events)
        
        # Calculate availability
        available_time = total_time - total_downtime
        availability_percentage = (available_time / total_time) * 100
        
        # Determine compliance
        is_compliant = availability_percentage >= objective.target_value
        compliance_percentage = (availability_percentage / objective.target_value) * 100
        
        return SLAMeasurement(
            timestamp=datetime.now(),
            objective_name=objective.name,
            actual_value=availability_percentage,
            target_value=objective.target_value,
            compliance_percentage=compliance_percentage,
            is_compliant=is_compliant,
            measurement_period_start=start_time,
            measurement_period_end=end_time,
            sample_count=len(downtime_events),
            additional_data={
                "downtime_events": downtime_events,
                "total_downtime_seconds": total_downtime,
                "available_time_seconds": available_time
            }
        )
    
    def calculate_latency_sla(self, objective: SLAObjective, 
                            start_time: datetime, end_time: datetime) -> SLAMeasurement:
        """Calculate latency SLA (95th percentile)"""
        logger.info(f"Calculating latency for {objective.name}")
        
        # Generate sample response times (replace with actual data collection)
        response_times = self._generate_sample_response_times(start_time, end_time, objective.target_value)
        
        if not response_times:
            # No data available
            return SLAMeasurement(
                timestamp=datetime.now(),
                objective_name=objective.name,
                actual_value=0,
                target_value=objective.target_value,
                compliance_percentage=0,
                is_compliant=False,
                measurement_period_start=start_time,
                measurement_period_end=end_time,
                sample_count=0,
                additional_data={"error": "No data available"}
            )
        
        # Calculate 95th percentile
        p95_latency = np.percentile(response_times, 95)
        
        # Determine compliance (lower is better for latency)
        is_compliant = p95_latency <= objective.target_value
        compliance_percentage = (objective.target_value / p95_latency) * 100 if p95_latency > 0 else 100
        
        return SLAMeasurement(
            timestamp=datetime.now(),
            objective_name=objective.name,
            actual_value=p95_latency,
            target_value=objective.target_value,
            compliance_percentage=min(compliance_percentage, 100),
            is_compliant=is_compliant,
            measurement_period_start=start_time,
            measurement_period_end=end_time,
            sample_count=len(response_times),
            additional_data={
                "p50_latency": np.percentile(response_times, 50),
                "p95_latency": p95_latency,
                "p99_latency": np.percentile(response_times, 99),
                "mean_latency": np.mean(response_times),
                "min_latency": np.min(response_times),
                "max_latency": np.max(response_times)
            }
        )
    
    def calculate_error_rate_sla(self, objective: SLAObjective, 
                               start_time: datetime, end_time: datetime) -> SLAMeasurement:
        """Calculate error rate SLA"""
        logger.info(f"Calculating error rate for {objective.name}")
        
        # Generate sample request data (replace with actual data collection)
        total_requests, error_requests = self._generate_sample_error_data(start_time, end_time, objective.target_value)
        
        if total_requests == 0:
            return SLAMeasurement(
                timestamp=datetime.now(),
                objective_name=objective.name,
                actual_value=0,
                target_value=objective.target_value,
                compliance_percentage=100,
                is_compliant=True,
                measurement_period_start=start_time,
                measurement_period_end=end_time,
                sample_count=0,
                additional_data={"error": "No requests in period"}
            )
        
        # Calculate error rate
        error_rate = (error_requests / total_requests) * 100
        
        # Determine compliance (lower is better for error rate)
        is_compliant = error_rate <= objective.target_value
        compliance_percentage = (objective.target_value / error_rate) * 100 if error_rate > 0 else 100
        
        return SLAMeasurement(
            timestamp=datetime.now(),
            objective_name=objective.name,
            actual_value=error_rate,
            target_value=objective.target_value,
            compliance_percentage=min(compliance_percentage, 100),
            is_compliant=is_compliant,
            measurement_period_start=start_time,
            measurement_period_end=end_time,
            sample_count=total_requests,
            additional_data={
                "total_requests": total_requests,
                "error_requests": error_requests,
                "success_requests": total_requests - error_requests,
                "error_rate_per_hour": error_requests / ((end_time - start_time).total_seconds() / 3600)
            }
        )
    
    def _generate_sample_downtime(self, start_time: datetime, end_time: datetime, 
                                 target_availability: float) -> List[Dict[str, Any]]:
        """Generate sample downtime events for demonstration"""
        # In real implementation, this would query actual monitoring data
        downtime_events = []
        
        # Simulate some downtime based on target
        total_hours = (end_time - start_time).total_seconds() / 3600
        allowed_downtime_hours = total_hours * (1 - target_availability / 100)
        
        if allowed_downtime_hours > 0:
            # Create a few downtime events
            num_events = max(1, int(allowed_downtime_hours / 2))
            for i in range(num_events):
                event_start = start_time + timedelta(hours=i * (total_hours / num_events))
                event_duration = allowed_downtime_hours * 3600 / num_events  # Convert to seconds
                
                downtime_events.append({
                    "start_time": event_start.isoformat(),
                    "end_time": (event_start + timedelta(seconds=event_duration)).isoformat(),
                    "duration": event_duration,
                    "reason": "Sample downtime event"
                })
        
        return downtime_events
    
    def _generate_sample_response_times(self, start_time: datetime, end_time: datetime, 
                                      target_latency: float) -> List[float]:
        """Generate sample response times for demonstration"""
        # In real implementation, this would query actual performance data
        num_samples = 1000
        
        # Generate response times with some variation around target
        base_latency = target_latency * 0.8  # Most responses are better than target
        variation = target_latency * 0.3
        
        response_times = []
        for _ in range(num_samples):
            # Add some outliers
            if np.random.random() < 0.05:  # 5% outliers
                latency = np.random.normal(target_latency * 1.5, target_latency * 0.5)
            else:
                latency = np.random.normal(base_latency, variation)
            
            response_times.append(max(0, latency))  # Ensure non-negative
        
        return response_times
    
    def _generate_sample_error_data(self, start_time: datetime, end_time: datetime, 
                                  target_error_rate: float) -> Tuple[int, int]:
        """Generate sample error data for demonstration"""
        # In real implementation, this would query actual log/metrics data
        hours = (end_time - start_time).total_seconds() / 3600
        requests_per_hour = 1000
        total_requests = int(hours * requests_per_hour)
        
        # Generate errors around target rate with some variation
        actual_error_rate = target_error_rate * np.random.uniform(0.5, 1.5)
        error_requests = int(total_requests * actual_error_rate / 100)
        
        return total_requests, error_requests
    
    def calculate_all_objectives(self, time_window_days: int = None) -> List[SLAMeasurement]:
        """Calculate SLA for all objectives"""
        measurements = []
        
        for objective in self.objectives:
            window_days = time_window_days or objective.time_window_days
            end_time = datetime.now()
            start_time = end_time - timedelta(days=window_days)
            
            try:
                if objective.metric_type == "availability":
                    measurement = self.calculate_availability_sla(objective, start_time, end_time)
                elif objective.metric_type == "latency":
                    measurement = self.calculate_latency_sla(objective, start_time, end_time)
                elif objective.metric_type == "error_rate":
                    measurement = self.calculate_error_rate_sla(objective, start_time, end_time)
                else:
                    logger.warning(f"Unknown metric type: {objective.metric_type}")
                    continue
                
                measurements.append(measurement)
                
            except Exception as e:
                logger.error(f"Error calculating SLA for {objective.name}: {str(e)}")
                continue
        
        return measurements
    
    def analyze_compliance_trend(self, measurements: List[SLAMeasurement]) -> List[Dict[str, Any]]:
        """Analyze compliance trends over time"""
        # Group measurements by objective
        objective_measurements = defaultdict(list)
        for measurement in measurements:
            objective_measurements[measurement.objective_name].append(measurement)
        
        trends = []
        
        for objective_name, obj_measurements in objective_measurements.items():
            # Sort by timestamp
            obj_measurements.sort(key=lambda x: x.timestamp)
            
            if len(obj_measurements) < 2:
                continue
            
            # Calculate trend
            compliance_values = [m.compliance_percentage for m in obj_measurements]
            timestamps = [m.timestamp for m in obj_measurements]
            
            # Simple linear trend calculation
            x = np.arange(len(compliance_values))
            if len(x) > 1:
                slope, intercept = np.polyfit(x, compliance_values, 1)
                trend_direction = "improving" if slope > 0 else "degrading" if slope < 0 else "stable"
            else:
                trend_direction = "stable"
                slope = 0
            
            trends.append({
                "objective_name": objective_name,
                "trend_direction": trend_direction,
                "slope": slope,
                "current_compliance": compliance_values[-1],
                "previous_compliance": compliance_values[-2] if len(compliance_values) > 1 else compliance_values[-1],
                "compliance_change": compliance_values[-1] - compliance_values[-2] if len(compliance_values) > 1 else 0,
                "data_points": len(compliance_values)
            })
        
        return trends
    
    def generate_breach_alerts(self, measurements: List[SLAMeasurement]) -> List[Dict[str, Any]]:
        """Generate alerts for SLA breaches"""
        alerts = []
        
        for measurement in measurements:
            objective = next((obj for obj in self.objectives if obj.name == measurement.objective_name), None)
            if not objective:
                continue
            
            # Check for actual breach
            if not measurement.is_compliant:
                alerts.append({
                    "type": "sla_breach",
                    "severity": "critical",
                    "objective_name": measurement.objective_name,
                    "actual_value": measurement.actual_value,
                    "target_value": measurement.target_value,
                    "compliance_percentage": measurement.compliance_percentage,
                    "message": f"SLA breach for {measurement.objective_name}: {measurement.actual_value:.2f} {objective.target_unit} (target: {measurement.target_value} {objective.target_unit})"
                })
            
            # Check for approaching breach
            elif measurement.compliance_percentage < objective.alerting_threshold:
                alerts.append({
                    "type": "sla_warning",
                    "severity": "warning",
                    "objective_name": measurement.objective_name,
                    "actual_value": measurement.actual_value,
                    "target_value": measurement.target_value,
                    "compliance_percentage": measurement.compliance_percentage,
                    "message": f"SLA warning for {measurement.objective_name}: approaching breach threshold"
                })
        
        return alerts
    
    def generate_recommendations(self, measurements: List[SLAMeasurement], 
                              trends: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on SLA analysis"""
        recommendations = []
        
        # Check for current breaches
        breaches = [m for m in measurements if not m.is_compliant]
        if breaches:
            recommendations.append(f"Immediate action required: {len(breaches)} SLA objectives currently breached.")
        
        # Check for degrading trends
        degrading = [t for t in trends if t["trend_direction"] == "degrading"]
        if degrading:
            recommendations.append(f"Monitor closely: {len(degrading)} objectives show degrading performance trends.")
        
        # Check for low compliance
        low_compliance = [m for m in measurements if m.compliance_percentage < 95]
        if low_compliance:
            recommendations.append(f"Performance optimization needed: {len(low_compliance)} objectives below 95% compliance.")
        
        # Specific recommendations based on metric types
        for measurement in measurements:
            if measurement.metric_type == "availability" and measurement.actual_value < 99:
                recommendations.append(f"Improve availability for {measurement.objective_name}: implement redundancy and failover mechanisms.")
            elif measurement.metric_type == "latency" and not measurement.is_compliant:
                recommendations.append(f"Optimize performance for {measurement.objective_name}: review code efficiency and infrastructure.")
            elif measurement.metric_type == "error_rate" and not measurement.is_compliant:
                recommendations.append(f"Reduce error rate for {measurement.objective_name}: improve error handling and input validation.")
        
        # General recommendations
        recommendations.extend([
            "Implement automated monitoring and alerting for all SLA objectives.",
            "Regularly review and update SLA targets based on business requirements.",
            "Conduct root cause analysis for any SLA breaches.",
            "Consider implementing SRE practices like error budgets and blameless post-mortems."
        ])
        
        return recommendations
    
    def calculate_overall_compliance(self, measurements: List[SLAMeasurement]) -> float:
        """Calculate overall SLA compliance across all objectives"""
        if not measurements:
            return 0.0
        
        total_compliance = sum(m.compliance_percentage for m in measurements)
        overall_compliance = total_compliance / len(measurements)
        
        return overall_compliance
    
    def generate_report(self, measurements: List[SLAMeasurement]) -> Dict[str, Any]:
        """Generate comprehensive SLA report"""
        # Calculate trends and alerts
        trends = self.analyze_compliance_trend(measurements)
        alerts = self.generate_breach_alerts(measurements)
        recommendations = self.generate_recommendations(measurements, trends)
        
        # Calculate overall compliance
        overall_compliance = self.calculate_overall_compliance(measurements)
        
        # Generate objectives summary
        objectives_summary = {}
        for measurement in measurements:
            objectives_summary[measurement.objective_name] = {
                "actual_value": measurement.actual_value,
                "target_value": measurement.target_value,
                "compliance_percentage": measurement.compliance_percentage,
                "is_compliant": measurement.is_compliant,
                "metric_type": next((obj.metric_type for obj in self.objectives if obj.name == measurement.objective_name), "unknown"),
                "target_unit": next((obj.target_unit for obj in self.objectives if obj.name == measurement.objective_name), "unknown")
            }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "reporting_period": {
                "start": min(m.measurement_period_start for m in measurements).isoformat() if measurements else datetime.now().isoformat(),
                "end": max(m.measurement_period_end for m in measurements).isoformat() if measurements else datetime.now().isoformat()
            },
            "objectives_summary": objectives_summary,
            "overall_compliance": overall_compliance,
            "compliance_trend": trends,
            "breach_alerts": alerts,
            "recommendations": recommendations,
            "detailed_measurements": [asdict(m) for m in measurements]
        }
    
    def save_report(self, report: Dict[str, Any], output_formats: List[str]):
        """Save report in specified formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if 'json' in output_formats:
            json_file = f"sla_slo_report_{timestamp}.json"
            with open(json_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"JSON report saved to: {json_file}")
        
        if 'csv' in output_formats:
            csv_file = f"sla_slo_report_{timestamp}.csv"
            self._save_csv_report(report, csv_file)
            logger.info(f"CSV report saved to: {csv_file}")
        
        if 'dashboard' in output_formats:
            dashboard_file = f"sla_slo_dashboard_{timestamp}.png"
            self._generate_dashboard(report, dashboard_file)
            logger.info(f"Dashboard saved to: {dashboard_file}")
    
    def _save_csv_report(self, report: Dict[str, Any], filename: str):
        """Save report as CSV"""
        # Objectives summary CSV
        objectives_data = []
        for name, summary in report["objectives_summary"].items():
            objectives_data.append({
                'Objective': name,
                'Metric Type': summary["metric_type"],
                'Actual Value': summary["actual_value"],
                'Target Value': summary["target_value"],
                'Unit': summary["target_unit"],
                'Compliance %': summary["compliance_percentage"],
                'Is Compliant': summary["is_compliant"]
            })
        
        df = pd.DataFrame(objectives_data)
        df.to_csv(filename, index=False)
    
    def _generate_dashboard(self, report: Dict[str, Any], filename: str):
        """Generate SLA dashboard"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('SLA/SLO Dashboard', fontsize=16)
        
        # 1. Overall compliance gauge
        overall_compliance = report["overall_compliance"]
        axes[0, 0].pie([overall_compliance, 100-overall_compliance], 
                      labels=['Compliant', 'Non-Compliant'], 
                      colors=['green', 'red'], autopct='%1.1f%%')
        axes[0, 0].set_title(f'Overall Compliance: {overall_compliance:.1f}%')
        
        # 2. Individual objective compliance
        objectives = list(report["objectives_summary"].keys())
        compliances = [report["objectives_summary"][obj]["compliance_percentage"] for obj in objectives]
        colors = ['green' if c >= 100 else 'orange' if c >= 95 else 'red' for c in compliances]
        
        axes[0, 1].barh(objectives, compliances, color=colors)
        axes[0, 1].set_title('Objective Compliance')
        axes[0, 1].set_xlabel('Compliance %')
        axes[0, 1].axvline(x=100, color='red', linestyle='--', alpha=0.7)
        axes[0, 1].set_xlim(0, max(compliances + [120]))
        
        # 3. Actual vs Target values
        actual_values = [report["objectives_summary"][obj]["actual_value"] for obj in objectives]
        target_values = [report["objectives_summary"][obj]["target_value"] for obj in objectives]
        
        x = np.arange(len(objectives))
        width = 0.35
        
        axes[1, 0].bar(x - width/2, actual_values, width, label='Actual', color='skyblue')
        axes[1, 0].bar(x + width/2, target_values, width, label='Target', color='lightcoral')
        axes[1, 0].set_title('Actual vs Target Values')
        axes[1, 0].set_ylabel('Value')
        axes[1, 0].set_xticks(x)
        axes[1, 0].set_xticklabels(objectives, rotation=45, ha='right')
        axes[1, 0].legend()
        
        # 4. Compliance trend (if available)
        if report["compliance_trend"]:
            trend_names = [t["objective_name"] for t in report["compliance_trend"]]
            trend_slopes = [t["slope"] for t in report["compliance_trend"]]
            trend_colors = ['green' if s > 0 else 'red' if s < 0 else 'gray' for s in trend_slopes]
            
            axes[1, 1].barh(trend_names, trend_slopes, color=trend_colors)
            axes[1, 1].set_title('Compliance Trend (Slope)')
            axes[1, 1].set_xlabel('Trend Slope')
            axes[1, 1].axvline(x=0, color='black', linestyle='-', alpha=0.3)
        else:
            axes[1, 1].text(0.5, 0.5, 'No trend data available', 
                           ha='center', va='center', transform=axes[1, 1].transAxes)
            axes[1, 1].set_title('Compliance Trend')
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Calculate SLA/SLO compliance')
    parser.add_argument('--config', type=str, default='config/sla_slo_config.json', 
                       help='Configuration file path')
    parser.add_argument('--time-window', type=int, help='Time window in days for calculations')
    parser.add_argument('--output-format', nargs='+', default=['json', 'dashboard'], 
                       choices=['json', 'csv', 'dashboard'], help='Output formats')
    
    args = parser.parse_args()
    
    try:
        calculator = SLASLOCalculator(args.config)
        
        # Calculate SLA for all objectives
        measurements = calculator.calculate_all_objectives(args.time_window)
        
        if not measurements:
            logger.warning("No measurements calculated")
            return
        
        # Generate report
        report = calculator.generate_report(measurements)
        
        # Save report
        calculator.save_report(report, args.output_format)
        
        # Print summary
        print(f"\n=== SLA/SLO Summary ===")
        print(f"Overall compliance: {report['overall_compliance']:.1f}%")
        print(f"Objectives measured: {len(measurements)}")
        print(f"Compliant objectives: {len([m for m in measurements if m.is_compliant])}")
        print(f"Breach alerts: {len(report['breach_alerts'])}")
        
        if report['breach_alerts']:
            print(f"\n🚨 SLA Breaches:")
            for alert in report['breach_alerts']:
                print(f"  - {alert['message']}")
        
        if report['recommendations']:
            print(f"\n📋 Key Recommendations:")
            for i, rec in enumerate(report['recommendations'][:5], 1):
                print(f"{i}. {rec}")
        
        logger.info("SLA/SLO calculation completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during SLA/SLO calculation: {str(e)}")
        raise

if __name__ == "__main__":
    main()
