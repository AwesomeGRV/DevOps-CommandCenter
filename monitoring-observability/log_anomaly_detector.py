#!/usr/bin/env python3
"""
Log Anomaly Detector
Author: DevOps-CommandCenter
Description: Detect anomalies in log patterns and alert on unusual activity
"""

import re
import json
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import statistics

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class LogAnomaly:
    timestamp: datetime
    anomaly_type: str
    severity: str
    description: str
    log_sample: str
    confidence_score: float
    affected_services: List[str]
    recommended_action: str

class LogAnomalyDetector:
    def __init__(self):
        self.baseline_patterns = {}
        self.error_thresholds = {
            'error_rate': 0.05,  # 5% error rate threshold
            'response_time': 2000,  # 2 seconds
            'log_volume': 1000  # logs per minute
        }
    
    def analyze_logs(self, log_file: str, time_window_hours: int = 1) -> List[LogAnomaly]:
        """Analyze log file for anomalies"""
        anomalies = []
        
        # Parse logs
        log_entries = self._parse_log_file(log_file)
        
        if not log_entries:
            logger.warning("No log entries found")
            return anomalies
        
        # Filter by time window
        cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
        recent_logs = [log for log in log_entries if log['timestamp'] >= cutoff_time]
        
        # Detect different types of anomalies
        anomalies.extend(self._detect_error_rate_spikes(recent_logs))
        anomalies.extend(self._detect_unusual_patterns(recent_logs))
        anomalies.extend(self._detect_volume_anomalies(recent_logs))
        anomalies.extend(self._detect_response_time_anomalies(recent_logs))
        anomalies.extend(self._detect_security_events(recent_logs))
        
        return sorted(anomalies, key=lambda x: x.timestamp, reverse=True)
    
    def _parse_log_file(self, log_file: str) -> List[Dict]:
        """Parse log file into structured format"""
        log_entries = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        entry = self._parse_log_line(line.strip())
                        if entry:
                            log_entries.append(entry)
                    except Exception as e:
                        logger.debug(f"Could not parse log line: {str(e)}")
        
        except FileNotFoundError:
            logger.error(f"Log file not found: {log_file}")
        except Exception as e:
            logger.error(f"Error reading log file: {str(e)}")
        
        return log_entries
    
    def _parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse a single log line"""
        # Common log formats
        patterns = [
            # Apache/Nginx access log
            r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+) (?P<response_time>\d+)',
            
            # Application log with timestamp
            r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<service>\S+): (?P<message>.*)',
            
            # JSON log
            r'^(?P<json_log>\{.*\})$',
            
            # Generic timestamp + message
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?) (?P<message>.*)'
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                if 'json_log' in match.groupdict():
                    try:
                        data = json.loads(match.group('json_log'))
                        return {
                            'timestamp': self._parse_timestamp(data.get('timestamp', data.get('@timestamp', ''))),
                            'level': data.get('level', data.get('severity', 'INFO')),
                            'service': data.get('service', data.get('application', 'unknown')),
                            'message': data.get('message', data.get('msg', line)),
                            'raw': line
                        }
                    except json.JSONDecodeError:
                        continue
                
                groups = match.groupdict()
                timestamp = self._parse_timestamp(groups.get('timestamp', ''))
                
                return {
                    'timestamp': timestamp,
                    'level': groups.get('level', 'INFO'),
                    'service': groups.get('service', 'unknown'),
                    'message': groups.get('message', line),
                    'raw': line,
                    'status': groups.get('status'),
                    'response_time': int(groups.get('response_time', 0)) if groups.get('response_time') else None
                }
        
        # Fallback - treat as plain text with current timestamp
        return {
            'timestamp': datetime.now(),
            'level': 'INFO',
            'service': 'unknown',
            'message': line,
            'raw': line
        }
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime object"""
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%SZ',
            '%d/%b/%Y:%H:%M:%S %z',
            '%Y-%m-%d %H:%M:%S,%f'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        # Fallback to current time
        return datetime.now()
    
    def _detect_error_rate_spikes(self, logs: List[Dict]) -> List[LogAnomaly]:
        """Detect spikes in error rates"""
        anomalies = []
        
        # Group logs by minute
        minute_groups = defaultdict(list)
        for log in logs:
            minute = log['timestamp'].replace(second=0, microsecond=0)
            minute_groups[minute].append(log)
        
        # Calculate error rates
        error_rates = {}
        for minute, minute_logs in minute_groups.items():
            total_logs = len(minute_logs)
            error_logs = len([l for l in minute_logs if l['level'].upper() in ['ERROR', 'FATAL', 'CRITICAL']])
            
            if total_logs > 0:
                error_rates[minute] = error_logs / total_logs
        
        # Detect spikes
        if len(error_rates) > 5:
            avg_error_rate = statistics.mean(error_rates.values())
            std_dev = statistics.stdev(error_rates.values()) if len(error_rates) > 1 else 0
            
            threshold = avg_error_rate + (2 * std_dev)
            
            for minute, error_rate in error_rates.items():
                if error_rate > max(threshold, self.error_thresholds['error_rate']):
                    anomalies.append(LogAnomaly(
                        timestamp=minute,
                        anomaly_type="error_rate_spike",
                        severity="high" if error_rate > 0.1 else "medium",
                        description=f"Error rate spike detected: {error_rate:.2%}",
                        log_sample=next((l['raw'] for l in minute_groups[minute] if l['level'].upper() in ['ERROR', 'FATAL', 'CRITICAL']), ""),
                        confidence_score=min(error_rate / self.error_thresholds['error_rate'], 1.0),
                        affected_services=list(set(l['service'] for l in minute_groups[minute])),
                        recommended_action="Investigate root cause of errors and check service health"
                    ))
        
        return anomalies
    
    def _detect_unusual_patterns(self, logs: List[Dict]) -> List[LogAnomaly]:
        """Detect unusual log patterns"""
        anomalies = []
        
        # Extract common patterns
        patterns = []
        for log in logs:
            # Simple pattern extraction - first few words
            words = log['message'].split()[:5]
            pattern = ' '.join(words)
            patterns.append(pattern)
        
        # Count pattern frequencies
        pattern_counts = Counter(patterns)
        
        # Find rare patterns (appear less than 3 times)
        rare_patterns = {p: c for p, c in pattern_counts.items() if c < 3}
        
        for pattern, count in rare_patterns.items():
            # Find logs with this pattern
            matching_logs = [l for l in logs if ' '.join(l['message'].split()[:5]) == pattern]
            
            for log in matching_logs:
                anomalies.append(LogAnomaly(
                    timestamp=log['timestamp'],
                    anomaly_type="unusual_pattern",
                    severity="low",
                    description=f"Unusual log pattern detected (appears {count} times)",
                    log_sample=log['raw'],
                    confidence_score=0.5,
                    affected_services=[log['service']],
                    recommended_action="Monitor this pattern for recurrence"
                ))
        
        return anomalies
    
    def _detect_volume_anomalies(self, logs: List[Dict]) -> List[LogAnomaly]:
        """Detect anomalies in log volume"""
        anomalies = []
        
        # Group logs by minute
        minute_counts = defaultdict(int)
        for log in logs:
            minute = log['timestamp'].replace(second=0, microsecond=0)
            minute_counts[minute] += 1
        
        if len(minute_counts) > 5:
            counts = list(minute_counts.values())
            avg_volume = statistics.mean(counts)
            std_dev = statistics.stdev(counts) if len(counts) > 1 else 0
            
            threshold = avg_volume + (2 * std_dev)
            
            for minute, count in minute_counts.items():
                if count > max(threshold, self.error_thresholds['log_volume']):
                    anomalies.append(LogAnomaly(
                        timestamp=minute,
                        anomaly_type="volume_spike",
                        severity="medium",
                        description=f"Log volume spike: {count} logs/minute (avg: {avg_volume:.0f})",
                        log_sample=f"High volume detected at {minute}",
                        confidence_score=min(count / self.error_thresholds['log_volume'], 1.0),
                        affected_services=list(set(l['service'] for l in logs if l['timestamp'].replace(second=0, microsecond=0) == minute)),
                        recommended_action="Check for potential issues causing high log volume"
                    ))
        
        return anomalies
    
    def _detect_response_time_anomalies(self, logs: List[Dict]) -> List[LogAnomaly]:
        """Detect response time anomalies"""
        anomalies = []
        
        # Extract response times
        response_times = []
        for log in logs:
            if log.get('response_time'):
                response_times.append({
                    'timestamp': log['timestamp'],
                    'response_time': log['response_time'],
                    'service': log['service']
                })
        
        if len(response_times) > 10:
            times = [rt['response_time'] for rt in response_times]
            avg_time = statistics.mean(times)
            std_dev = statistics.stdev(times)
            
            threshold = avg_time + (2 * std_dev)
            
            for rt_data in response_times:
                if rt_data['response_time'] > max(threshold, self.error_thresholds['response_time']):
                    anomalies.append(LogAnomaly(
                        timestamp=rt_data['timestamp'],
                        anomaly_type="response_time_anomaly",
                        severity="medium" if rt_data['response_time'] > 5000 else "low",
                        description=f"High response time: {rt_data['response_time']}ms (avg: {avg_time:.0f}ms)",
                        log_sample=f"Response time: {rt_data['response_time']}ms",
                        confidence_score=min(rt_data['response_time'] / self.error_thresholds['response_time'], 1.0),
                        affected_services=[rt_data['service']],
                        recommended_action="Investigate performance bottlenecks"
                    ))
        
        return anomalies
    
    def _detect_security_events(self, logs: List[Dict]) -> List[LogAnomaly]:
        """Detect potential security events"""
        anomalies = []
        
        # Security-related patterns
        security_patterns = [
            r'(?i)failed.*login',
            r'(?i)unauthorized.*access',
            r'(?i)suspicious.*activity',
            r'(?i)brute.*force',
            r'(?i)sql.*injection',
            r'(?i)xss.*attack',
            r'(?i)malicious.*request',
            r'(?i)blocked.*ip'
        ]
        
        for log in logs:
            message = log['message']
            for pattern in security_patterns:
                if re.search(pattern, message):
                    anomalies.append(LogAnomaly(
                        timestamp=log['timestamp'],
                        anomaly_type="security_event",
                        severity="high",
                        description=f"Potential security event detected: {pattern}",
                        log_sample=log['raw'],
                        confidence_score=0.8,
                        affected_services=[log['service']],
                        recommended_action="Investigate potential security threat immediately"
                    ))
                    break
        
        return anomalies
    
    def generate_report(self, anomalies: List[LogAnomaly]) -> Dict[str, Any]:
        """Generate anomaly detection report"""
        # Group by severity
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        for anomaly in anomalies:
            severity_counts[anomaly.severity] += 1
            type_counts[anomaly.anomaly_type] += 1
        
        # Recent anomalies (last hour)
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_anomalies = [a for a in anomalies if a.timestamp >= one_hour_ago]
        
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_anomalies": len(anomalies),
                "recent_anomalies": len(recent_anomalies),
                "severity_breakdown": dict(severity_counts),
                "type_breakdown": dict(type_counts)
            },
            "anomalies": [asdict(a) for a in anomalies],
            "recommendations": self._generate_overall_recommendations(anomalies)
        }
    
    def _generate_overall_recommendations(self, anomalies: List[LogAnomaly]) -> List[str]:
        """Generate overall recommendations based on anomalies"""
        recommendations = []
        
        if not anomalies:
            recommendations.append("No anomalies detected - system appears stable")
            return recommendations
        
        # High severity recommendations
        high_severity = [a for a in anomalies if a.severity == 'high']
        if high_severity:
            recommendations.append(f"URGENT: {len(high_severity)} high-severity anomalies detected - immediate investigation required")
        
        # Type-specific recommendations
        error_anomalies = [a for a in anomalies if a.anomaly_type == 'error_rate_spike']
        if error_anomalies:
            recommendations.append(f"Error rate spikes detected - review application logs and check service health")
        
        security_anomalies = [a for a in anomalies if a.anomaly_type == 'security_event']
        if security_anomalies:
            recommendations.append(f"Security events detected - review access logs and consider security measures")
        
        performance_anomalies = [a for a in anomalies if a.anomaly_type == 'response_time_anomaly']
        if performance_anomalies:
            recommendations.append(f"Performance issues detected - investigate bottlenecks and consider scaling")
        
        # General recommendations
        if len(anomalies) > 10:
            recommendations.append("High number of anomalies detected - consider reviewing system health")
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='Detect anomalies in log files')
    parser.add_argument('log_file', help='Log file to analyze')
    parser.add_argument('--output', default='log_anomaly_report.json')
    parser.add_argument('--time-window', type=int, default=1, help='Time window in hours to analyze')
    
    args = parser.parse_args()
    
    try:
        detector = LogAnomalyDetector()
        anomalies = detector.analyze_logs(args.log_file, args.time_window)
        report = detector.generate_report(anomalies)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Log Anomaly Detection Summary:")
        print(f"Total anomalies: {report['summary']['total_anomalies']}")
        print(f"Recent anomalies: {report['summary']['recent_anomalies']}")
        print(f"High severity: {report['summary']['severity_breakdown'].get('high', 0)}")
        print(f"Medium severity: {report['summary']['severity_breakdown'].get('medium', 0)}")
        print(f"Low severity: {report['summary']['severity_breakdown'].get('low', 0)}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error during anomaly detection: {str(e)}")

if __name__ == "__main__":
    main()
