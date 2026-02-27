#!/usr/bin/env python3
"""
MTTR Calculator (Mean Time To Resolve)
Author: CloudOps-SRE-Toolkit
Description: Calculate and track Mean Time To Resolve metrics for incidents
"""

import json
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import statistics

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Incident:
    id: str
    title: str
    severity: str
    created_at: datetime
    resolved_at: Optional[datetime]
    acknowledged_at: Optional[datetime]
    assigned_at: Optional[datetime]
    description: str
    assignee: str
    tags: List[str]

@dataclass
class MTTRMetrics:
    mttr_minutes: float
    mta_minutes: float  # Mean Time to Acknowledge
    mttf_minutes: float  # Mean Time to Fix
    total_incidents: int
    resolved_incidents: int
    severity_breakdown: Dict[str, float]
    trend: str

class MTTRCalculator:
    def __init__(self):
        self.incidents = []
    
    def load_incidents(self, incidents_data: List[Dict]) -> List[Incident]:
        incidents = []
        
        for incident_data in incidents_data:
            incident = Incident(
                id=incident_data['id'],
                title=incident_data['title'],
                severity=incident_data['severity'],
                created_at=datetime.fromisoformat(incident_data['created_at']),
                resolved_at=datetime.fromisoformat(incident_data['resolved_at']) if incident_data.get('resolved_at') else None,
                acknowledged_at=datetime.fromisoformat(incident_data['acknowledged_at']) if incident_data.get('acknowledged_at') else None,
                assigned_at=datetime.fromisoformat(incident_data['assigned_at']) if incident_data.get('assigned_at') else None,
                description=incident_data.get('description', ''),
                assignee=incident_data.get('assignee', 'unassigned'),
                tags=incident_data.get('tags', [])
            )
            incidents.append(incident)
        
        return incidents
    
    def calculate_mttr(self, incidents: List[Incident], days: int = 30) -> MTTRMetrics:
        # Filter incidents within the specified period
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_incidents = [i for i in incidents if i.created_at >= cutoff_date]
        
        # Calculate metrics for resolved incidents
        resolved_incidents = [i for i in recent_incidents if i.resolved_at]
        
        if not resolved_incidents:
            return MTTRMetrics(
                mttr_minutes=0,
                mta_minutes=0,
                mttf_minutes=0,
                total_incidents=len(recent_incidents),
                resolved_incidents=0,
                severity_breakdown={},
                trend="insufficient_data"
            )
        
        # Calculate MTTR (Mean Time To Resolve)
        resolution_times = []
        for incident in resolved_incidents:
            resolution_time = (incident.resolved_at - incident.created_at).total_seconds() / 60
            resolution_times.append(resolution_time)
        
        mttr = statistics.mean(resolution_times)
        
        # Calculate MTA (Mean Time to Acknowledge)
        acknowledgment_times = []
        for incident in resolved_incidents:
            if incident.acknowledged_at:
                ack_time = (incident.acknowledged_at - incident.created_at).total_seconds() / 60
                acknowledgment_times.append(ack_time)
        
        mta = statistics.mean(acknowledgment_times) if acknowledgment_times else 0
        
        # Calculate MTTF (Mean Time To Fix)
        fix_times = []
        for incident in resolved_incidents:
            if incident.acknowledged_at and incident.assigned_at:
                fix_time = (incident.resolved_at - incident.assigned_at).total_seconds() / 60
                fix_times.append(fix_time)
        
        mttf = statistics.mean(fix_times) if fix_times else mttr
        
        # Calculate severity breakdown
        severity_times = {}
        for incident in resolved_incidents:
            resolution_time = (incident.resolved_at - incident.created_at).total_seconds() / 60
            if incident.severity not in severity_times:
                severity_times[incident.severity] = []
            severity_times[incident.severity].append(resolution_time)
        
        severity_breakdown = {}
        for severity, times in severity_times.items():
            severity_breakdown[severity] = statistics.mean(times)
        
        # Calculate trend (simplified)
        trend = "stable"
        if len(resolved_incidents) >= 10:
            first_half = resolved_incidents[:len(resolved_incidents)//2]
            second_half = resolved_incidents[len(resolved_incidents)//2:]
            
            first_mttr = statistics.mean([(i.resolved_at - i.created_at).total_seconds() / 60 for i in first_half])
            second_mttr = statistics.mean([(i.resolved_at - i.created_at).total_seconds() / 60 for i in second_half])
            
            if second_mttr < first_mttr * 0.9:
                trend = "improving"
            elif second_mttr > first_mttr * 1.1:
                trend = "degrading"
        
        return MTTRMetrics(
            mttr_minutes=mttr,
            mta_minutes=mta,
            mttf_minutes=mttf,
            total_incidents=len(recent_incidents),
            resolved_incidents=len(resolved_incidents),
            severity_breakdown=severity_breakdown,
            trend=trend
        )
    
    def generate_sample_data(self) -> List[Dict]:
        # Generate sample incident data for demonstration
        incidents = []
        base_date = datetime.now() - timedelta(days=30)
        
        for i in range(50):
            created_date = base_date + timedelta(days=i//2, hours=i%24)
            severity = ['critical', 'high', 'medium', 'low'][i % 4]
            
            # Most incidents get resolved within 1-4 hours
            resolution_hours = [1, 2, 3, 4, 6, 8, 12, 24][i % 8]
            resolved_date = created_date + timedelta(hours=resolution_hours)
            
            incidents.append({
                'id': f'INC-{i+1:04d}',
                'title': f'Incident {i+1}: System {severity} issue',
                'severity': severity,
                'created_at': created_date.isoformat(),
                'resolved_at': resolved_date.isoformat(),
                'acknowledged_at': (created_date + timedelta(minutes=15)).isoformat(),
                'assigned_at': (created_date + timedelta(minutes=30)).isoformat(),
                'description': f'Sample {severity} incident for demonstration',
                'assignee': f'engineer{i%5}',
                'tags': [severity, 'production']
            })
        
        return incidents

def main():
    parser = argparse.ArgumentParser(description='Calculate MTTR metrics')
    parser.add_argument('--input', help='JSON file with incident data')
    parser.add_argument('--days', type=int, default=30, help='Number of days to analyze')
    parser.add_argument('--output', default='mttr_report.json')
    parser.add_argument('--sample', action='store_true', help='Generate sample data')
    
    args = parser.parse_args()
    
    try:
        calculator = MTTRCalculator()
        
        if args.sample:
            incidents_data = calculator.generate_sample_data()
        elif args.input:
            with open(args.input, 'r') as f:
                incidents_data = json.load(f)
        else:
            print("Please provide --input file or use --sample to generate sample data")
            return
        
        incidents = calculator.load_incidents(incidents_data)
        metrics = calculator.calculate_mttr(incidents, args.days)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "analysis_period_days": args.days,
            "metrics": asdict(metrics),
            "recommendations": [
                "Aim to reduce MTTR below 60 minutes for critical incidents",
                "Implement automated alerting to reduce MTA",
                "Create runbooks for common incident types",
                "Conduct blameless post-mortems to improve processes"
            ]
        }
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"MTTR Analysis Summary:")
        print(f"Period: Last {args.days} days")
        print(f"Total incidents: {metrics.total_incidents}")
        print(f"Resolved incidents: {metrics.resolved_incidents}")
        print(f"MTTR: {metrics.mttr_minutes:.1f} minutes")
        print(f"MTA: {metrics.mta_minutes:.1f} minutes")
        print(f"MTTF: {metrics.mttf_minutes:.1f} minutes")
        print(f"Trend: {metrics.trend}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
