#!/usr/bin/env python3
"""
Pipeline Failure Notifier
Author: CloudOps-SRE-Toolkit
Description: Monitor CI/CD pipelines and send notifications for failures
"""

import os
import json
import logging
import argparse
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PipelineFailure:
    pipeline_name: str
    project: str
    branch: str
    commit_hash: str
    commit_message: str
    failure_time: datetime
    failure_reason: str
    failed_stage: str
    error_logs: str
    assignee: str
    severity: str

class PipelineFailureNotifier:
    def __init__(self, config_file: str = "config/pipeline_config.json"):
        self.config = self._load_config(config_file)
        self.webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        self.teams_url = os.getenv("TEAMS_WEBHOOK_URL", "")
        self.email_enabled = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "pipelines": [
                {
                    "name": "main-build",
                    "project": "web-app",
                    "repository": "github.com/company/web-app",
                    "monitored_branches": ["main", "develop"],
                    "notification_channels": ["slack", "email"],
                    "assignees": ["devops-team@company.com"],
                    "severity_threshold": "high"
                }
            ],
            "monitoring": {
                "check_interval_minutes": 5,
                "failure_threshold": 3,
                "auto_assign_on_failure": True,
                "include_logs": True,
                "max_log_lines": 50
            }
        }
    
    def monitor_pipelines(self) -> List[PipelineFailure]:
        failures = []
        
        for pipeline_config in self.config.get("pipelines", []):
            try:
                pipeline_failures = self._check_pipeline(pipeline_config)
                failures.extend(pipeline_failures)
            except Exception as e:
                logger.error(f"Error monitoring pipeline {pipeline_config['name']}: {str(e)}")
        
        return failures
    
    def _check_pipeline(self, pipeline_config: Dict) -> List[PipelineFailure]:
        # This would integrate with actual CI/CD systems (Jenkins, GitLab CI, GitHub Actions, etc.)
        # For demonstration, we'll simulate failure detection
        
        failures = []
        
        # Simulate checking recent pipeline runs
        recent_runs = self._get_recent_pipeline_runs(pipeline_config)
        
        for run in recent_runs:
            if run['status'] == 'failed':
                failure = PipelineFailure(
                    pipeline_name=pipeline_config['name'],
                    project=pipeline_config['project'],
                    branch=run['branch'],
                    commit_hash=run['commit'],
                    commit_message=run['message'],
                    failure_time=run['timestamp'],
                    failure_reason=run['failure_reason'],
                    failed_stage=run['failed_stage'],
                    error_logs=run['error_logs'],
                    assignee=self._determine_assignee(pipeline_config, run),
                    severity=self._determine_severity(pipeline_config, run)
                )
                failures.append(failure)
        
        return failures
    
    def _get_recent_pipeline_runs(self, pipeline_config: Dict) -> List[Dict]:
        # Simulate pipeline runs - in real implementation, this would query CI/CD API
        return [
            {
                'status': 'failed',
                'branch': 'main',
                'commit': 'abc123',
                'message': 'Fix critical bug in authentication',
                'timestamp': datetime.now() - timedelta(minutes=10),
                'failure_reason': 'Test suite failed',
                'failed_stage': 'test',
                'error_logs': 'ERROR: Authentication test failed\nExpected: 200\nActual: 401'
            }
        ]
    
    def _determine_assignee(self, pipeline_config: Dict, run: Dict) -> str:
        # Logic to determine who should be assigned
        # Could be based on commit author, on-call schedule, etc.
        assignees = pipeline_config.get('assignees', [])
        return assignees[0] if assignees else "devops-team@company.com"
    
    def _determine_severity(self, pipeline_config: Dict, run: Dict) -> str:
        # Determine severity based on branch, failure type, etc.
        if run['branch'] == 'main':
            return 'critical'
        elif run['branch'] in ['develop', 'staging']:
            return 'high'
        else:
            return 'medium'
    
    def send_notifications(self, failures: List[PipelineFailure]):
        for failure in failures:
            try:
                # Send Slack notification
                if self.webhook_url:
                    self._send_slack_notification(failure)
                
                # Send Teams notification
                if self.teams_url:
                    self._send_teams_notification(failure)
                
                # Send email notification
                if self.email_enabled:
                    self._send_email_notification(failure)
                
                logger.info(f"Notifications sent for failure in {failure.pipeline_name}")
            
            except Exception as e:
                logger.error(f"Error sending notifications for {failure.pipeline_name}: {str(e)}")
    
    def _send_slack_notification(self, failure: PipelineFailure):
        payload = {
            "attachments": [{
                "color": "danger" if failure.severity == "critical" else "warning",
                "title": f"Pipeline Failure: {failure.pipeline_name}",
                "title_link": f"https://github.com/{failure.project}/actions",
                "fields": [
                    {"title": "Project", "value": failure.project, "short": True},
                    {"title": "Branch", "value": failure.branch, "short": True},
                    {"title": "Failed Stage", "value": failure.failed_stage, "short": True},
                    {"title": "Severity", "value": failure.severity.upper(), "short": True},
                    {"title": "Commit", "value": f"`{failure.commit_hash[:8]}`", "short": True},
                    {"title": "Assignee", "value": failure.assignee, "short": True}
                ],
                "text": f"*Failure Reason:* {failure.failure_reason}\n*Commit Message:* {failure.commit_message}",
                "footer": "Pipeline Failure Notifier",
                "ts": int(failure.failure_time.timestamp())
            }]
        }
        
        response = requests.post(self.webhook_url, json=payload, timeout=10)
        response.raise_for_status()
    
    def _send_teams_notification(self, failure: PipelineFailure):
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000" if failure.severity == "critical" else "FFA500",
            "sections": [{
                "activityTitle": f"Pipeline Failure: {failure.pipeline_name}",
                "activitySubtitle": f"Project: {failure.project} | Branch: {failure.branch}",
                "facts": [
                    {"name": "Failed Stage", "value": failure.failed_stage},
                    {"name": "Severity", "value": failure.severity.upper()},
                    {"name": "Commit", "value": failure.commit_hash[:8]},
                    {"name": "Assignee", "value": failure.assignee}
                ],
                "markdown": True,
                "text": f"**Failure Reason:** {failure.failure_reason}\n**Commit Message:** {failure.commit_message}"
            }]
        }
        
        response = requests.post(self.teams_url, json=payload, timeout=10)
        response.raise_for_status()
    
    def _send_email_notification(self, failure: PipelineFailure):
        # Email implementation would go here
        # This is a placeholder for email sending logic
        logger.info(f"Email notification would be sent to {failure.assignee} for {failure.pipeline_name}")
    
    def generate_report(self, failures: List[PipelineFailure]) -> Dict[str, Any]:
        severity_counts = {}
        project_counts = {}
        
        for failure in failures:
            severity_counts[failure.severity] = severity_counts.get(failure.severity, 0) + 1
            project_counts[failure.project] = project_counts.get(failure.project, 0) + 1
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_failures": len(failures),
            "severity_breakdown": severity_counts,
            "affected_projects": len(project_counts),
            "failures": [asdict(f) for f in failures]
        }

def main():
    parser = argparse.ArgumentParser(description='Monitor and notify on pipeline failures')
    parser.add_argument('--config', default='config/pipeline_config.json')
    parser.add_argument('--output', default='pipeline_failures_report.json')
    parser.add_argument('--dry-run', action='store_true', help='Check without sending notifications')
    
    args = parser.parse_args()
    
    try:
        notifier = PipelineFailureNotifier(args.config)
        failures = notifier.monitor_pipelines()
        
        if not args.dry_run:
            notifier.send_notifications(failures)
        
        report = notifier.generate_report(failures)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Pipeline Failure Summary:")
        print(f"Total failures: {report['total_failures']}")
        print(f"Critical: {report['severity_breakdown'].get('critical', 0)}")
        print(f"High: {report['severity_breakdown'].get('high', 0)}")
        print(f"Medium: {report['severity_breakdown'].get('medium', 0)}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
