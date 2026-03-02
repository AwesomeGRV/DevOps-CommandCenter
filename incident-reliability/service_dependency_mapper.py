#!/usr/bin/env python3
"""
Service Dependency Mapper
Author: DevOps-CommandCenter
Description: Map and analyze service dependencies for impact analysis
"""

import json
import logging
import argparse
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ServiceDependency:
    service_name: str
    dependencies: List[str]
    dependents: List[str]
    dependency_type: str  # sync, async, shared_resource
    criticality: str  # critical, important, optional
    impact_score: float
    failure_impact: str

class ServiceDependencyMapper:
    def __init__(self):
        self.dependency_graph = nx.DiGraph()
        self.services = {}
        self.critical_paths = []
    
    def map_dependencies(self, config_file: str = None) -> Dict[str, Any]:
        """Map service dependencies from configuration or auto-discovery"""
        if config_file:
            dependencies = self._load_from_config(config_file)
        else:
            dependencies = self._auto_discover_dependencies()
        
        # Build dependency graph
        self._build_graph(dependencies)
        
        # Analyze dependencies
        analysis = self._analyze_dependencies()
        
        return analysis
    
    def _load_from_config(self, config_file: str) -> List[Dict]:
        """Load dependencies from configuration file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            return config.get('services', [])
        
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found, using sample data")
            return self._get_sample_dependencies()
    
    def _get_sample_dependencies(self) -> List[Dict]:
        """Get sample service dependencies for demonstration"""
        return [
            {
                "name": "web-frontend",
                "dependencies": ["api-gateway", "auth-service"],
                "type": "sync",
                "criticality": "critical"
            },
            {
                "name": "api-gateway",
                "dependencies": ["user-service", "order-service", "payment-service"],
                "type": "sync",
                "criticality": "critical"
            },
            {
                "name": "user-service",
                "dependencies": ["database", "cache"],
                "type": "sync",
                "criticality": "critical"
            },
            {
                "name": "order-service",
                "dependencies": ["database", "inventory-service", "notification-service"],
                "type": "sync",
                "criticality": "important"
            },
            {
                "name": "payment-service",
                "dependencies": ["database", "payment-processor"],
                "type": "sync",
                "criticality": "critical"
            },
            {
                "name": "inventory-service",
                "dependencies": ["database"],
                "type": "sync",
                "criticality": "important"
            },
            {
                "name": "notification-service",
                "dependencies": ["email-service", "sms-service"],
                "type": "async",
                "criticality": "optional"
            },
            {
                "name": "database",
                "dependencies": [],
                "type": "shared_resource",
                "criticality": "critical"
            },
            {
                "name": "cache",
                "dependencies": [],
                "type": "shared_resource",
                "criticality": "important"
            },
            {
                "name": "email-service",
                "dependencies": [],
                "type": "sync",
                "criticality": "optional"
            },
            {
                "name": "sms-service",
                "dependencies": [],
                "type": "sync",
                "criticality": "optional"
            },
            {
                "name": "payment-processor",
                "dependencies": [],
                "type": "sync",
                "criticality": "critical"
            }
        ]
    
    def _auto_discover_dependencies(self) -> List[Dict]:
        """Auto-discover dependencies from system"""
        # In practice, this would analyze:
        # - Service mesh configurations
        # - API calls in logs
        # - Network traffic
        # - Configuration files
        # - Container orchestrator data
        
        logger.info("Auto-discovering dependencies...")
        
        # Placeholder implementation
        return self._get_sample_dependencies()
    
    def _build_graph(self, dependencies: List[Dict]):
        """Build dependency graph"""
        self.dependency_graph.clear()
        
        # Add nodes and edges
        for service in dependencies:
            service_name = service['name']
            
            # Add service node
            self.dependency_graph.add_node(
                service_name,
                type=service['type'],
                criticality=service['criticality']
            )
            
            # Add dependency edges
            for dep in service['dependencies']:
                self.dependency_graph.add_edge(service_name, dep)
        
        # Calculate graph metrics
        self._calculate_graph_metrics()
    
    def _calculate_graph_metrics(self):
        """Calculate graph metrics for each service"""
        for service in self.dependency_graph.nodes():
            # Calculate centrality metrics
            in_degree = self.dependency_graph.in_degree(service)
            out_degree = self.dependency_graph.out_degree(service)
            
            # Calculate betweenness centrality
            try:
                betweenness = nx.betweenness_centrality(self.dependency_graph)[service]
            except:
                betweenness = 0.0
            
            # Calculate impact score
            impact_score = self._calculate_impact_score(service, in_degree, out_degree, betweenness)
            
            # Determine failure impact
            failure_impact = self._determine_failure_impact(service, impact_score)
            
            # Store service data
            self.services[service] = {
                'dependencies': list(self.dependency_graph.successors(service)),
                'dependents': list(self.dependency_graph.predecessors(service)),
                'in_degree': in_degree,
                'out_degree': out_degree,
                'betweenness': betweenness,
                'impact_score': impact_score,
                'failure_impact': failure_impact
            }
    
    def _calculate_impact_score(self, service: str, in_degree: int, 
                              out_degree: int, betweenness: float) -> float:
        """Calculate impact score for a service"""
        # Get service criticality
        criticality = self.dependency_graph.nodes[service].get('criticality', 'optional')
        
        # Base score from graph metrics
        base_score = (in_degree * 0.3) + (out_degree * 0.2) + (betweenness * 100 * 0.5)
        
        # Apply criticality multiplier
        criticality_multipliers = {
            'critical': 2.0,
            'important': 1.5,
            'optional': 1.0
        }
        
        multiplier = criticality_multipliers.get(criticality, 1.0)
        
        return min(base_score * multiplier, 100.0)
    
    def _determine_failure_impact(self, service: str, impact_score: float) -> str:
        """Determine failure impact level"""
        if impact_score >= 80:
            return "catastrophic"
        elif impact_score >= 60:
            return "severe"
        elif impact_score >= 40:
            return "moderate"
        elif impact_score >= 20:
            return "minor"
        else:
            return "minimal"
    
    def _analyze_dependencies(self) -> Dict[str, Any]:
        """Perform comprehensive dependency analysis"""
        analysis = {
            "timestamp": datetime.now().isoformat(),
            "summary": self._generate_summary(),
            "critical_services": self._identify_critical_services(),
            "single_points_of_failure": self._identify_single_points_of_failure(),
            "dependency_chains": self._analyze_dependency_chains(),
            "circular_dependencies": self._detect_circular_dependencies(),
            "impact_analysis": self._perform_impact_analysis(),
            "recommendations": self._generate_recommendations()
        }
        
        return analysis
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        total_services = len(self.dependency_graph.nodes())
        total_dependencies = len(self.dependency_graph.edges())
        
        # Count by criticality
        criticality_counts = {}
        for service in self.dependency_graph.nodes():
            crit = self.dependency_graph.nodes[service].get('criticality', 'optional')
            criticality_counts[crit] = criticality_counts.get(crit, 0) + 1
        
        # Count by type
        type_counts = {}
        for service in self.dependency_graph.nodes():
            stype = self.dependency_graph.nodes[service].get('type', 'sync')
            type_counts[stype] = type_counts.get(stype, 0) + 1
        
        return {
            "total_services": total_services,
            "total_dependencies": total_dependencies,
            "average_dependencies_per_service": total_dependencies / total_services if total_services > 0 else 0,
            "criticality_breakdown": criticality_counts,
            "type_breakdown": type_counts,
            "graph_density": nx.density(self.dependency_graph)
        }
    
    def _identify_critical_services(self) -> List[Dict]:
        """Identify most critical services"""
        services_with_metrics = []
        
        for service, metrics in self.services.items():
            services_with_metrics.append({
                "name": service,
                "impact_score": metrics['impact_score'],
                "failure_impact": metrics['failure_impact'],
                "dependents": len(metrics['dependents']),
                "dependencies": len(metrics['dependencies']),
                "criticality": self.dependency_graph.nodes[service].get('criticality', 'optional')
            })
        
        # Sort by impact score
        return sorted(services_with_metrics, key=lambda x: x['impact_score'], reverse=True)
    
    def _identify_single_points_of_failure(self) -> List[Dict]:
        """Identify single points of failure"""
        spofs = []
        
        for service in self.dependency_graph.nodes():
            # Check if service is a single point of failure
            dependents = list(self.dependency_graph.predecessors(service))
            
            if len(dependents) > 1:  # Service has multiple dependents
                # Check if dependents have alternative paths
                is_spof = True
                
                for dependent in dependents:
                    # Check if dependent has alternative dependencies
                    alt_deps = [d for d in self.dependency_graph.successors(dependent) if d != service]
                    if not alt_deps:
                        is_spof = False
                        break
                
                if is_spof:
                    spofs.append({
                        "service": service,
                        "affected_services": dependents,
                        "impact_score": self.services[service]['impact_score'],
                        "recommendation": "Add redundancy or failover mechanisms"
                    })
        
        return sorted(spofs, key=lambda x: x['impact_score'], reverse=True)
    
    def _analyze_dependency_chains(self) -> List[Dict]:
        """Analyze dependency chains"""
        chains = []
        
        # Find longest paths
        try:
            longest_paths = []
            for source in self.dependency_graph.nodes():
                for target in self.dependency_graph.nodes():
                    if source != target and nx.has_path(self.dependency_graph, source, target):
                        path = nx.shortest_path(self.dependency_graph, source, target)
                        if len(path) > 2:  # Only chains with 3+ services
                            longest_paths.append(path)
            
            # Get unique longest chains
            unique_chains = []
            seen = set()
            
            for path in longest_paths:
                path_tuple = tuple(path)
                if path_tuple not in seen:
                    seen.add(path_tuple)
                    unique_chains.append(path)
            
            # Sort by length
            unique_chains.sort(key=len, reverse=True)
            
            # Take top 10 chains
            for chain in unique_chains[:10]:
                chains.append({
                    "chain": chain,
                    "length": len(chain),
                    "critical_services": [s for s in chain if self.dependency_graph.nodes[s].get('criticality') == 'critical']
                })
        
        except Exception as e:
            logger.warning(f"Error analyzing dependency chains: {str(e)}")
        
        return chains
    
    def _detect_circular_dependencies(self) -> List[List[str]]:
        """Detect circular dependencies"""
        try:
            cycles = list(nx.simple_cycles(self.dependency_graph))
            return cycles
        except Exception as e:
            logger.warning(f"Error detecting circular dependencies: {str(e)}")
            return []
    
    def _perform_impact_analysis(self) -> Dict[str, Any]:
        """Perform impact analysis for service failures"""
        impact_analysis = {}
        
        for service in self.dependency_graph.nodes():
            # Calculate downstream impact
            downstream_reachable = []
            try:
                downstream_reachable = list(nx.descendants(self.dependency_graph, service))
            except:
                pass
            
            # Calculate upstream impact
            upstream_reachable = []
            try:
                upstream_reachable = list(nx.ancestors(self.dependency_graph, service))
            except:
                pass
            
            impact_analysis[service] = {
                "downstream_services": downstream_reachable,
                "upstream_services": upstream_reachable,
                "total_affected": len(downstream_reachable) + len(upstream_reachable),
                "critical_downstream": [s for s in downstream_reachable 
                                      if self.dependency_graph.nodes[s].get('criticality') == 'critical'],
                "critical_upstream": [s for s in upstream_reachable 
                                    if self.dependency_graph.nodes[s].get('criticality') == 'critical']
            }
        
        return impact_analysis
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        # Check for circular dependencies
        cycles = self._detect_circular_dependencies()
        if cycles:
            recommendations.append(f"Found {len(cycles)} circular dependencies - resolve to prevent deadlocks")
        
        # Check for single points of failure
        spofs = self._identify_single_points_of_failure()
        if spofs:
            recommendations.append(f"Found {len(spofs)} single points of failure - implement redundancy")
        
        # Check for highly connected services
        highly_connected = [s for s, m in self.services.items() if m['impact_score'] > 80]
        if highly_connected:
            recommendations.append(f"Found {len(highly_connected)} high-impact services - ensure high availability")
        
        # Check for long dependency chains
        chains = self._analyze_dependency_chains()
        long_chains = [c for c in chains if c['length'] > 5]
        if long_chains:
            recommendations.append(f"Found {len(long_chains)} long dependency chains - consider breaking them down")
        
        # General recommendations
        recommendations.extend([
            "Implement circuit breakers for critical dependencies",
            "Add monitoring for all service dependencies",
            "Create dependency health checks",
            "Document all service dependencies",
            "Regularly review and update dependency mappings"
        ])
        
        return recommendations
    
    def generate_dependency_graph_visualization(self, output_file: str = "dependency_graph.png"):
        """Generate visualization of dependency graph"""
        try:
            plt.figure(figsize=(15, 10))
            
            # Create layout
            pos = nx.spring_layout(self.dependency_graph, k=2, iterations=50)
            
            # Draw nodes with different colors based on criticality
            node_colors = []
            for node in self.dependency_graph.nodes():
                criticality = self.dependency_graph.nodes[node].get('criticality', 'optional')
                if criticality == 'critical':
                    node_colors.append('red')
                elif criticality == 'important':
                    node_colors.append('orange')
                else:
                    node_colors.append('lightblue')
            
            # Draw the graph
            nx.draw(self.dependency_graph, pos, 
                   with_labels=True, 
                   node_color=node_colors,
                   node_size=1500,
                   font_size=8,
                   font_weight='bold',
                   arrows=True,
                   arrowsize=20,
                   edge_color='gray',
                   width=2)
            
            # Add title
            plt.title("Service Dependency Graph", fontsize=16, fontweight='bold')
            
            # Add legend
            from matplotlib.patches import Patch
            legend_elements = [
                Patch(facecolor='red', label='Critical'),
                Patch(facecolor='orange', label='Important'),
                Patch(facecolor='lightblue', label='Optional')
            ]
            plt.legend(handles=legend_elements, loc='upper right')
            
            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Dependency graph saved to {output_file}")
        
        except Exception as e:
            logger.error(f"Error generating graph visualization: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Map and analyze service dependencies')
    parser.add_argument('--config', help='Configuration file with service dependencies')
    parser.add_argument('--output', default='service_dependency_analysis.json')
    parser.add_argument('--graph', default='dependency_graph.png', help='Output file for dependency graph')
    
    args = parser.parse_args()
    
    try:
        mapper = ServiceDependencyMapper()
        analysis = mapper.map_dependencies(args.config)
        
        # Save analysis report
        with open(args.output, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        
        # Generate visualization
        mapper.generate_dependency_graph_visualization(args.graph)
        
        # Print summary
        print(f"Service Dependency Analysis Summary:")
        print(f"Total services: {analysis['summary']['total_services']}")
        print(f"Total dependencies: {analysis['summary']['total_dependencies']}")
        print(f"Critical services: {len(analysis['critical_services'])}")
        print(f"Single points of failure: {len(analysis['single_points_of_failure'])}")
        print(f"Circular dependencies: {len(analysis['circular_dependencies'])}")
        print(f"Analysis report saved to {args.output}")
        print(f"Dependency graph saved to {args.graph}")
        
    except Exception as e:
        logger.error(f"Error during dependency mapping: {str(e)}")

if __name__ == "__main__":
    main()
