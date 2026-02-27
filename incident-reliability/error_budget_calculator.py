#!/usr/bin/env python3
"""
Error Budget Calculator
Author: CloudOps-SRE-Toolkit
Description: Calculate and track error budgets for SLO compliance
"""

import json
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ErrorBudget:
    slo_name: str
    target_percentage: float
    period_days: int
    total_events: int
    bad_events: int
    good_events: int
    actual_slo: float
    error_budget_remaining: float
    error_budget_consumed: float
    budget_status: str  # healthy, warning, depleted
    recommendations: List[str]

class ErrorBudgetCalculator:
    def __init__(self):
        pass
    
    def calculate_error_budget(self, slo_config: Dict, events_data: List[Dict]) -> ErrorBudget:
        slo_name = slo_config['name']
        target_percentage = slo_config['target_percentage']
        period_days = slo_config['period_days']
        
        # Calculate period
        end_date = datetime.now()
        start_date = end_date - timedelta(days=period_days)
        
        # Filter events within period
        period_events = [
            event for event in events_data
            if start_date <= datetime.fromisoformat(event['timestamp']) <= end_date
        ]
        
        total_events = len(period_events)
        bad_events = len([e for e in period_events if not e['success']])
        good_events = total_events - bad_events
        
        if total_events == 0:
            return ErrorBudget(
                slo_name=slo_name,
                target_percentage=target_percentage,
                period_days=period_days,
                total_events=0,
                bad_events=0,
                good_events=0,
                actual_slo=100.0,
                error_budget_remaining=100.0,
                error_budget_consumed=0.0,
                budget_status="no_data",
                recommendations=["No events data available for analysis"]
            )
        
        # Calculate actual SLO
        actual_slo = (good_events / total_events) * 100
        
        # Calculate error budget
        error_budget_percentage = 100 - target_percentage
        error_budget_consumed = max(0, target_percentage - actual_slo)
        error_budget_remaining = error_budget_percentage - error_budget_consumed
        
        # Determine status
        if error_budget_remaining < 0:
            budget_status = "depleted"
        elif error_budget_remaining < error_budget_percentage * 0.2:  # Less than 20% remaining
            budget_status = "warning"
        else:
            budget_status = "healthy"
        
        # Generate recommendations
        recommendations = self._generate_recommendations(budget_status, error_budget_consumed, target_percentage)
        
        return ErrorBudget(
            slo_name=slo_name,
            target_percentage=target_percentage,
            period_days=period_days,
            total_events=total_events,
            bad_events=bad_events,
            good_events=good_events,
            actual_slo=actual_slo,
            error_budget_remaining=error_budget_remaining,
            error_budget_consumed=error_budget_consumed,
            budget_status=budget_status,
            recommendations=recommendations
        )
    
    def _generate_recommendations(self, status: str, consumed: float, target: float) -> List[str]:
        recommendations = []
        
        if status == "depleted":
            recommendations.extend([
                "CRITICAL: Error budget depleted! SLO breached.",
                "Immediate incident response required.",
                "Implement emergency measures to restore service.",
                "Conduct post-mortem to prevent recurrence."
            ])
        elif status == "warning":
            recommendations.extend([
                "WARNING: Error budget running low.",
                "Increase monitoring and alerting.",
                "Prepare incident response plans.",
                "Consider throttling non-critical features."
            ])
        else:
            recommendations.extend([
                "Error budget is healthy.",
                "Continue monitoring service performance.",
                "Maintain current reliability practices."
            ])
        
        if consumed > target * 0.1:  # More than 10% consumed
            recommendations.append("Review recent incidents for patterns.")
        
        return recommendations
    
    def generate_sample_data(self) -> tuple:
        # Generate sample SLO configuration
        slo_config = {
            "name": "API Availability",
            "target_percentage": 99.9,
            "period_days": 30
        }
        
        # Generate sample events data
        events = []
        base_date = datetime.now() - timedelta(days=30)
        
        for i in range(10000):  # 10,000 events over 30 days
            timestamp = base_date + timedelta(minutes=i*4.32)  # ~4.32 minutes apart
            # 99.9% success rate = 1 failure per 1000 events
            success = i % 1000 != 0  # Every 1000th event fails
            
            events.append({
                "timestamp": timestamp.isoformat(),
                "success": success,
                "response_time_ms": 200 + (i % 500),
                "error_code": None if success else "500"
            })
        
        return slo_config, events

def main():
    parser = argparse.ArgumentParser(description='Calculate error budgets')
    parser.add_argument('--slo-config', help='JSON file with SLO configuration')
    parser.add_argument('--events-data', help='JSON file with events data')
    parser.add_argument('--output', default='error_budget_report.json')
    parser.add_argument('--sample', action='store_true', help='Generate sample data')
    
    args = parser.parse_args()
    
    try:
        calculator = ErrorBudgetCalculator()
        
        if args.sample:
            slo_config, events_data = calculator.generate_sample_data()
        else:
            if not args.slo_config or not args.events_data:
                print("Please provide --slo-config and --events-data files or use --sample")
                return
            
            with open(args.slo_config, 'r') as f:
                slo_config = json.load(f)
            
            with open(args.events_data, 'r') as f:
                events_data = json.load(f)
        
        error_budget = calculator.calculate_error_budget(slo_config, events_data)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "error_budget": asdict(error_budget),
            "summary": {
                "slo_name": error_budget.slo_name,
                "target": f"{error_budget.target_percentage}%",
                "actual": f"{error_budget.actual_slo:.2f}%",
                "budget_status": error_budget.budget_status,
                "budget_remaining": f"{error_budget.error_budget_remaining:.2f}%",
                "budget_consumed": f"{error_budget.error_budget_consumed:.2f}%"
            }
        }
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Error Budget Analysis:")
        print(f"SLO: {error_budget.slo_name}")
        print(f"Target: {error_budget.target_percentage}%")
        print(f"Actual: {error_budget.actual_slo:.2f}%")
        print(f"Budget Status: {error_budget.budget_status}")
        print(f"Budget Remaining: {error_budget.error_budget_remaining:.2f}%")
        print(f"Budget Consumed: {error_budget.error_budget_consumed:.2f}%")
        print(f"Total Events: {error_budget.total_events}")
        print(f"Bad Events: {error_budget.bad_events}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
