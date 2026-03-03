#!/usr/bin/env python3
"""
Chaos Engineering Runner
Author: DevOps-CommandCenter
Description: Execute chaos engineering experiments to test system resilience
"""

import json
import logging
import argparse
import time
import random
import threading
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ChaosExperiment:
    name: str
    experiment_type: str
    target: str
    parameters: Dict[str, Any]
    status: str  # pending, running, completed, failed, aborted
    start_time: datetime
    end_time: Optional[datetime]
    duration: float
    impact_score: float
    recovery_time: float
    success: bool
    observations: List[str]
    metrics: Dict[str, float]

class ChaosEngineeringRunner:
    def __init__(self, config_file: str = "config/chaos_config.json"):
        self.config = self._load_config(config_file)
        self.experiments = []
        self.is_running = False
        self.monitoring_data = {}
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load chaos engineering configuration"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default chaos configuration"""
        return {
            "safety_checks": {
                "enabled": True,
                "max_impact_score": 8.0,
                "require_approval": True,
                "business_hours_only": True,
                "blackout_windows": ["2024-12-25", "2024-01-01"]
            },
            "experiments": {
                "network_latency": {
                    "enabled": True,
                    "parameters": {
                        "latency_ms": 100,
                        "duration_seconds": 60,
                        "jitter_ms": 20,
                        "target_services": ["api-service", "database"]
                    }
                },
                "pod_deletion": {
                    "enabled": True,
                    "parameters": {
                        "count": 1,
                        "namespace": "default",
                        "label_selector": "app=web",
                        "grace_period_seconds": 0
                    }
                },
                "cpu_pressure": {
                    "enabled": True,
                    "parameters": {
                        "cpu_load": 80,
                        "duration_seconds": 120,
                        "target_pods": ["web-frontend"]
                    }
                },
                "memory_pressure": {
                    "enabled": True,
                    "parameters": {
                        "memory_usage_mb": 512,
                        "duration_seconds": 90,
                        "target_pods": ["api-service"]
                    }
                },
                "disk_pressure": {
                    "enabled": True,
                    "parameters": {
                        "disk_usage_percent": 85,
                        "duration_seconds": 60,
                        "target_nodes": ["worker-node-1"]
                    }
                },
                "network_partition": {
                    "enabled": True,
                    "parameters": {
                        "source_pods": ["frontend"],
                        "target_pods": ["backend"],
                        "duration_seconds": 30
                    }
                }
            },
            "monitoring": {
                "metrics": [
                    "response_time_p95",
                    "error_rate",
                    "throughput",
                    "cpu_usage",
                    "memory_usage"
                ],
                "alert_thresholds": {
                    "error_rate": 5.0,
                    "response_time_p95": 2000,
                    "cpu_usage": 90.0
                }
            },
            "rollback": {
                "enabled": True,
                "automatic": True,
                "timeout_seconds": 300
            }
        }
    
    def run_chaos_experiment(self, experiment_name: str, 
                           experiment_config: Dict = None) -> ChaosExperiment:
        """Run a specific chaos experiment"""
        if experiment_name not in self.config["experiments"]:
            raise ValueError(f"Unknown experiment: {experiment_name}")
        
        # Safety checks
        if not self._perform_safety_checks(experiment_name):
            raise RuntimeError("Safety checks failed - experiment aborted")
        
        # Get experiment configuration
        exp_config = self.config["experiments"][experiment_name]
        if experiment_config:
            exp_config.update(experiment_config)
        
        logger.info(f"Starting chaos experiment: {experiment_name}")
        
        # Create experiment object
        experiment = ChaosExperiment(
            name=experiment_name,
            experiment_type=experiment_name,
            target=str(exp_config.get("parameters", {}).get("target_services", ["unknown"])),
            parameters=exp_config["parameters"],
            status="pending",
            start_time=datetime.now(),
            end_time=None,
            duration=0,
            impact_score=0,
            recovery_time=0,
            success=False,
            observations=[],
            metrics={}
        )
        
        self.experiments.append(experiment)
        
        try:
            # Start monitoring
            self._start_monitoring(experiment)
            
            # Execute experiment
            experiment.status = "running"
            self._execute_experiment(experiment, exp_config)
            
            # Wait for experiment completion
            self._wait_for_completion(experiment, exp_config["parameters"].get("duration_seconds", 60))
            
            # Assess impact
            self._assess_impact(experiment)
            
            # Rollback if needed
            if self.config["rollback"]["enabled"]:
                self._rollback_experiment(experiment)
            
            experiment.status = "completed"
            experiment.success = True
            
        except Exception as e:
            logger.error(f"Experiment {experiment_name} failed: {str(e)}")
            experiment.status = "failed"
            experiment.success = False
            experiment.observations.append(f"Experiment failed: {str(e)}")
            
            # Emergency rollback
            if self.config["rollback"]["automatic"]:
                self._emergency_rollback(experiment)
        
        finally:
            experiment.end_time = datetime.now()
            experiment.duration = (experiment.end_time - experiment.start_time).total_seconds()
            
            # Stop monitoring
            self._stop_monitoring(experiment)
        
        return experiment
    
    def _perform_safety_checks(self, experiment_name: str) -> bool:
        """Perform safety checks before experiment"""
        if not self.config["safety_checks"]["enabled"]:
            return True
        
        # Check business hours
        if self.config["safety_checks"]["business_hours_only"]:
            current_hour = datetime.now().hour
            if current_hour < 9 or current_hour > 17:
                logger.warning("Experiment outside business hours")
                return False
        
        # Check blackout windows
        today = datetime.now().strftime("%Y-%m-%d")
        if today in self.config["safety_checks"]["blackout_windows"]:
            logger.warning("Experiment in blackout window")
            return False
        
        # Check for approval (simplified)
        if self.config["safety_checks"]["require_approval"]:
            logger.info("Experiment requires approval - proceeding in demo mode")
        
        return True
    
    def _start_monitoring(self, experiment: ChaosExperiment):
        """Start monitoring for experiment"""
        logger.info(f"Starting monitoring for {experiment.name}")
        
        # Start baseline collection
        self.monitoring_data[experiment.name] = {
            "baseline": self._collect_baseline_metrics(),
            "during": [],
            "recovery": []
        }
        
        # Start monitoring thread
        monitor_thread = threading.Thread(
            target=self._monitor_experiment,
            args=(experiment,)
        )
        monitor_thread.daemon = True
        monitor_thread.start()
    
    def _collect_baseline_metrics(self) -> Dict[str, float]:
        """Collect baseline metrics"""
        # Simulated metrics collection
        return {
            "response_time_p95": random.uniform(100, 500),
            "error_rate": random.uniform(0.1, 2.0),
            "throughput": random.uniform(800, 1200),
            "cpu_usage": random.uniform(20, 60),
            "memory_usage": random.uniform(30, 70)
        }
    
    def _monitor_experiment(self, experiment: ChaosExperiment):
        """Monitor experiment in real-time"""
        monitoring_interval = 5  # seconds
        
        while experiment.status == "running":
            try:
                # Collect current metrics
                current_metrics = self._collect_current_metrics()
                
                if experiment.name in self.monitoring_data:
                    self.monitoring_data[experiment.name]["during"].append({
                        "timestamp": datetime.now(),
                        "metrics": current_metrics
                    })
                
                # Check alert thresholds
                self._check_alert_thresholds(experiment, current_metrics)
                
                time.sleep(monitoring_interval)
                
            except Exception as e:
                logger.error(f"Monitoring error: {str(e)}")
                break
    
    def _collect_current_metrics(self) -> Dict[str, float]:
        """Collect current system metrics"""
        # Simulated metrics with some variation
        return {
            "response_time_p95": random.uniform(150, 800),
            "error_rate": random.uniform(0.5, 8.0),
            "throughput": random.uniform(600, 1000),
            "cpu_usage": random.uniform(40, 85),
            "memory_usage": random.uniform(45, 80)
        }
    
    def _check_alert_thresholds(self, experiment: ChaosExperiment, 
                              metrics: Dict[str, float]):
        """Check if metrics exceed alert thresholds"""
        thresholds = self.config["monitoring"]["alert_thresholds"]
        
        alerts = []
        
        if metrics["error_rate"] > thresholds["error_rate"]:
            alerts.append(f"High error rate: {metrics['error_rate']:.1f}%")
        
        if metrics["response_time_p95"] > thresholds["response_time_p95"]:
            alerts.append(f"High response time: {metrics['response_time_p95']:.0f}ms")
        
        if metrics["cpu_usage"] > thresholds["cpu_usage"]:
            alerts.append(f"High CPU usage: {metrics['cpu_usage']:.1f}%")
        
        if alerts:
            experiment.observations.extend(alerts)
            logger.warning(f"Alerts for {experiment.name}: {', '.join(alerts)}")
    
    def _execute_experiment(self, experiment: ChaosExperiment, config: Dict):
        """Execute the chaos experiment"""
        experiment_type = experiment.experiment_type
        parameters = config["parameters"]
        
        experiment.observations.append(f"Starting {experiment_type} with parameters: {parameters}")
        
        if experiment_type == "network_latency":
            self._inject_network_latency(parameters)
        elif experiment_type == "pod_deletion":
            self._delete_pods(parameters)
        elif experiment_type == "cpu_pressure":
            self._inject_cpu_pressure(parameters)
        elif experiment_type == "memory_pressure":
            self._inject_memory_pressure(parameters)
        elif experiment_type == "disk_pressure":
            self._inject_disk_pressure(parameters)
        elif experiment_type == "network_partition":
            self._create_network_partition(parameters)
        else:
            raise ValueError(f"Unknown experiment type: {experiment_type}")
        
        experiment.observations.append(f"Experiment {experiment_type} injected successfully")
    
    def _inject_network_latency(self, parameters: Dict):
        """Inject network latency"""
        latency_ms = parameters["latency_ms"]
        target_services = parameters["target_services"]
        
        logger.info(f"Injecting {latency_ms}ms latency to {target_services}")
        
        # Simulate network latency injection
        # In practice, this would use tc (traffic control) or service mesh
        
        experiment_command = f"tc qdisc add dev eth0 root netem delay {latency_ms}ms"
        logger.info(f"Would execute: {experiment_command}")
    
    def _delete_pods(self, parameters: Dict):
        """Delete Kubernetes pods"""
        count = parameters["count"]
        namespace = parameters["namespace"]
        label_selector = parameters["label_selector"]
        
        logger.info(f"Deleting {count} pods in namespace {namespace} with selector {label_selector}")
        
        # Simulate pod deletion
        experiment_command = f"kubectl delete pods -n {namespace} -l {label_selector} --grace-period={parameters.get('grace_period_seconds', 0)}"
        logger.info(f"Would execute: {experiment_command}")
    
    def _inject_cpu_pressure(self, parameters: Dict):
        """Inject CPU pressure"""
        cpu_load = parameters["cpu_load"]
        target_pods = parameters["target_pods"]
        
        logger.info(f"Injecting {cpu_load}% CPU load to {target_pods}")
        
        # Simulate CPU pressure injection
        for pod in target_pods:
            experiment_command = f"kubectl exec {pod} -- stress --cpu {cpu_load // 10} --timeout {parameters['duration_seconds']}s"
            logger.info(f"Would execute: {experiment_command}")
    
    def _inject_memory_pressure(self, parameters: Dict):
        """Inject memory pressure"""
        memory_mb = parameters["memory_usage_mb"]
        target_pods = parameters["target_pods"]
        
        logger.info(f"Injecting {memory_mb}MB memory pressure to {target_pods}")
        
        # Simulate memory pressure injection
        for pod in target_pods:
            experiment_command = f"kubectl exec {pod} -- stress --vm 1 --vm-bytes {memory_mb}M --timeout {parameters['duration_seconds']}s"
            logger.info(f"Would execute: {experiment_command}")
    
    def _inject_disk_pressure(self, parameters: Dict):
        """Inject disk pressure"""
        disk_usage = parameters["disk_usage_percent"]
        target_nodes = parameters["target_nodes"]
        
        logger.info(f"Injecting {disk_usage}% disk usage to {target_nodes}")
        
        # Simulate disk pressure injection
        for node in target_nodes:
            # Create large temporary file
            experiment_command = f"dd if=/dev/zero of=/tmp/stress_file bs=1M count=1024"
            logger.info(f"Would execute on {node}: {experiment_command}")
    
    def _create_network_partition(self, parameters: Dict):
        """Create network partition"""
        source_pods = parameters["source_pods"]
        target_pods = parameters["target_pods"]
        
        logger.info(f"Creating network partition between {source_pods} and {target_pods}")
        
        # Simulate network partition using iptables or network policies
        for source in source_pods:
            for target in target_pods:
                experiment_command = f"iptables -A OUTPUT -d {target} -j DROP"
                logger.info(f"Would execute on {source}: {experiment_command}")
    
    def _wait_for_completion(self, experiment: ChaosExperiment, duration_seconds: int):
        """Wait for experiment to complete"""
        logger.info(f"Waiting {duration_seconds} seconds for experiment completion")
        
        start_time = time.time()
        while time.time() - start_time < duration_seconds and experiment.status == "running":
            time.sleep(1)
    
    def _assess_impact(self, experiment: ChaosExperiment):
        """Assess experiment impact"""
        logger.info(f"Assessing impact for {experiment.name}")
        
        # Calculate impact score based on metrics deviation
        if experiment.name in self.monitoring_data:
            baseline = self.monitoring_data[experiment.name]["baseline"]
            during = self.monitoring_data[experiment.name]["during"]
            
            if during:
                # Calculate average metrics during experiment
                avg_metrics = {}
                for metric_name in baseline.keys():
                    values = [d["metrics"].get(metric_name, 0) for d in during]
                    avg_metrics[metric_name] = sum(values) / len(values) if values else 0
                
                # Calculate impact score
                impact_score = 0
                for metric_name, baseline_value in baseline.items():
                    current_value = avg_metrics.get(metric_name, baseline_value)
                    
                    if metric_name == "error_rate":
                        impact_score += max(0, (current_value - baseline_value) / baseline_value * 100)
                    elif metric_name == "response_time_p95":
                        impact_score += max(0, (current_value - baseline_value) / baseline_value * 50)
                    elif metric_name in ["cpu_usage", "memory_usage"]:
                        impact_score += max(0, (current_value - baseline_value) / baseline_value * 20)
                
                experiment.impact_score = min(impact_score, 10.0)
                experiment.metrics = avg_metrics
                
                experiment.observations.append(f"Impact score calculated: {experiment.impact_score:.2f}")
    
    def _rollback_experiment(self, experiment: ChaosExperiment):
        """Rollback experiment changes"""
        logger.info(f"Rolling back experiment {experiment.name}")
        
        # Simulate rollback
        if experiment.experiment_type == "network_latency":
            rollback_command = "tc qdisc del dev eth0 root"
            logger.info(f"Would execute: {rollback_command}")
        
        elif experiment.experiment_type == "network_partition":
            rollback_command = "iptables -F OUTPUT"
            logger.info(f"Would execute: {rollback_command}")
        
        # Monitor recovery
        recovery_start = time.time()
        self._monitor_recovery(experiment)
        experiment.recovery_time = time.time() - recovery_start
        
        experiment.observations.append(f"Rollback completed in {experiment.recovery_time:.1f} seconds")
    
    def _emergency_rollback(self, experiment: ChaosExperiment):
        """Emergency rollback for failed experiments"""
        logger.warning(f"Emergency rollback for {experiment.name}")
        
        # Immediate rollback commands
        emergency_commands = [
            "tc qdisc del dev eth0 root",
            "iptables -F",
            "killall stress",
            "rm -f /tmp/stress_file"
        ]
        
        for command in emergency_commands:
            logger.info(f"Emergency command: {command}")
        
        experiment.observations.append("Emergency rollback executed")
    
    def _monitor_recovery(self, experiment: ChaosExperiment):
        """Monitor system recovery after rollback"""
        recovery_timeout = self.config["rollback"]["timeout_seconds"]
        start_time = time.time()
        
        while time.time() - start_time < recovery_timeout:
            # Check if system has recovered
            current_metrics = self._collect_current_metrics()
            
            # Compare with baseline
            if experiment.name in self.monitoring_data:
                baseline = self.monitoring_data[experiment.name]["baseline"]
                
                recovered = True
                for metric_name, baseline_value in baseline.items():
                    current_value = current_metrics.get(metric_name, baseline_value)
                    
                    # Consider recovered if within 20% of baseline
                    if abs(current_value - baseline_value) / baseline_value > 0.2:
                        recovered = False
                        break
                
                if recovered:
                    experiment.observations.append("System recovered successfully")
                    break
            
            time.sleep(5)
        
        if time.time() - start_time >= recovery_timeout:
            experiment.observations.append("Recovery timeout - system may not have fully recovered")
    
    def _stop_monitoring(self, experiment: ChaosExperiment):
        """Stop monitoring for experiment"""
        logger.info(f"Stopping monitoring for {experiment.name}")
        
        # Collect recovery metrics
        if experiment.name in self.monitoring_data:
            recovery_metrics = self._collect_current_metrics()
            self.monitoring_data[experiment.name]["recovery"].append({
                "timestamp": datetime.now(),
                "metrics": recovery_metrics
            })
    
    def run_experiment_suite(self, experiment_names: List[str] = None) -> List[ChaosExperiment]:
        """Run a suite of chaos experiments"""
        if not experiment_names:
            experiment_names = [name for name, config in self.config["experiments"].items() 
                               if config["enabled"]]
        
        logger.info(f"Running chaos experiment suite: {experiment_names}")
        
        results = []
        
        for experiment_name in experiment_names:
            try:
                experiment = self.run_chaos_experiment(experiment_name)
                results.append(experiment)
                
                # Wait between experiments
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Failed to run experiment {experiment_name}: {str(e)}")
        
        return results
    
    def generate_report(self, experiments: List[ChaosExperiment]) -> Dict[str, Any]:
        """Generate chaos engineering report"""
        if not experiments:
            return {"error": "No experiments to report"}
        
        # Calculate statistics
        total_experiments = len(experiments)
        successful_experiments = len([e for e in experiments if e.success])
        failed_experiments = len([e for e in experiments if not e.success])
        
        avg_impact_score = sum(e.impact_score for e in experiments) / total_experiments
        avg_recovery_time = sum(e.recovery_time for e in experiments if e.recovery_time > 0) / len([e for e in experiments if e.recovery_time > 0])
        
        # Group by experiment type
        experiments_by_type = {}
        for exp in experiments:
            if exp.experiment_type not in experiments_by_type:
                experiments_by_type[exp.experiment_type] = []
            experiments_by_type[exp.experiment_type].append(exp)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_experiments": total_experiments,
                "successful": successful_experiments,
                "failed": failed_experiments,
                "success_rate": (successful_experiments / total_experiments * 100) if total_experiments > 0 else 0,
                "average_impact_score": avg_impact_score,
                "average_recovery_time": avg_recovery_time
            },
            "experiments_by_type": {
                exp_type: {
                    "count": len(exps),
                    "success_rate": len([e for e in exps if e.success]) / len(exps) * 100,
                    "avg_impact": sum(e.impact_score for e in exps) / len(exps)
                }
                for exp_type, exps in experiments_by_type.items()
            },
            "detailed_results": [asdict(exp) for exp in experiments],
            "recommendations": self._generate_recommendations(experiments)
        }
    
    def _generate_recommendations(self, experiments: List[ChaosExperiment]) -> List[str]:
        """Generate chaos engineering recommendations"""
        recommendations = []
        
        # Analyze experiment results
        high_impact_experiments = [e for e in experiments if e.impact_score > 7.0]
        slow_recovery_experiments = [e for e in experiments if e.recovery_time > 60]
        failed_experiments = [e for e in experiments if not e.success]
        
        if high_impact_experiments:
            recommendations.extend([
                f"Review {len(high_impact_experiments)} high-impact experiments for system vulnerabilities",
                "Implement additional resilience patterns for high-impact scenarios",
                "Consider adding circuit breakers and bulkheads"
            ])
        
        if slow_recovery_experiments:
            recommendations.extend([
                f"Improve recovery time for {len(slow_recovery_experiments)} experiments",
                "Implement automated recovery mechanisms",
                "Add health checks and readiness probes"
            ])
        
        if failed_experiments:
            recommendations.extend([
                f"Investigate {len(failed_experiments)} failed experiments",
                "Review rollback procedures and automation",
                "Add better monitoring and alerting"
            ])
        
        # General recommendations
        recommendations.extend([
            "Expand chaos engineering to cover more failure scenarios",
            "Implement regular chaos engineering schedule",
            "Integrate chaos experiments with CI/CD pipeline",
            "Document all chaos experiments and their results",
            "Share results with development and operations teams"
        ])
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='Run chaos engineering experiments')
    parser.add_argument('--config', default='config/chaos_config.json')
    parser.add_argument('--output', default='chaos_engineering_report.json')
    parser.add_argument('--experiment', help='Specific experiment to run')
    parser.add_argument('--suite', action='store_true', help='Run experiment suite')
    parser.add_argument('--experiments', nargs='+', 
                       choices=['network_latency', 'pod_deletion', 'cpu_pressure', 
                               'memory_pressure', 'disk_pressure', 'network_partition'],
                       help='Specific experiments to run in suite')
    
    args = parser.parse_args()
    
    try:
        runner = ChaosEngineeringRunner(args.config)
        
        if args.experiment:
            # Run single experiment
            experiment = runner.run_chaos_experiment(args.experiment)
            experiments = [experiment]
        elif args.suite:
            # Run experiment suite
            experiments = runner.run_experiment_suite(args.experiments)
        else:
            # Default: run all enabled experiments
            experiments = runner.run_experiment_suite()
        
        # Generate report
        report = runner.generate_report(experiments)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Print summary
        summary = report["summary"]
        print(f"Chaos Engineering Summary:")
        print(f"Total Experiments: {summary['total_experiments']}")
        print(f"Success Rate: {summary['success_rate']:.1f}%")
        print(f"Successful: {summary['successful']}")
        print(f"Failed: {summary['failed']}")
        print(f"Average Impact Score: {summary['average_impact_score']:.2f}")
        print(f"Average Recovery Time: {summary['average_recovery_time']:.1f}s")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error during chaos engineering: {str(e)}")

if __name__ == "__main__":
    main()
