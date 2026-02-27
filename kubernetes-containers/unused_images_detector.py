#!/usr/bin/env python3
"""
Kubernetes Unused Images Detector
Author: CloudOps-SRE-Toolkit
Description: Detect and analyze unused container images in Kubernetes clusters
"""

import os
import json
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import kubernetes
from kubernetes import client, config
import docker
import requests
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'unused_images_detection_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ImageInfo:
    """Data class for image information"""
    name: str
    tag: str
    repository: str
    digest: Optional[str] = None
    size_mb: Optional[float] = None
    created_at: Optional[str] = None
    last_used: Optional[str] = None
    usage_count: int = 0
    pods_using: List[str] = None
    namespaces_using: List[str] = None
    image_pull_policy: Optional[str] = None
    
    def __post_init__(self):
        if self.pods_using is None:
            self.pods_using = []
        if self.namespaces_using is None:
            self.namespaces_using = []

@dataclass
class UnusedImageReport:
    """Data class for unused image report"""
    timestamp: str
    total_images: int
    used_images: int
    unused_images: int
    potential_savings_mb: float
    unused_images_details: List[ImageInfo]
    usage_statistics: Dict[str, Any]
    recommendations: List[str]

class UnusedImagesDetector:
    """Detect unused container images in Kubernetes"""
    
    def __init__(self, config_file: str = "config/image_detection_config.json"):
        self.config = self._load_config(config_file)
        self.setup_kubernetes_client()
        self.setup_docker_client()
        self.image_registry = {}
        
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
            "namespaces": ["default", "kube-system", "production"],
            "exclude_namespaces": ["kube-public"],
            "exclude_images": [
                "k8s.gcr.io/pause",
                "kubernetes/pause"
            ],
            "retention_days": 30,
            "include_system_images": False,
            "docker_registry": {
                "check_registry": True,
                "registries": ["docker.io", "gcr.io", "quay.io", "ghcr.io"]
            },
            "output": {
                "format": ["json", "csv", "html"],
                "include_recommendations": True
            }
        }
    
    def setup_kubernetes_client(self):
        """Setup Kubernetes client"""
        try:
            config.load_incluster_config()
            logger.info("Loaded in-cluster Kubernetes config")
        except:
            try:
                config.load_kube_config()
                logger.info("Loaded kubeconfig")
            except Exception as e:
                logger.error(f"Failed to load Kubernetes config: {str(e)}")
                raise
        
        self.v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
    
    def setup_docker_client(self):
        """Setup Docker client"""
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize Docker client: {str(e)}")
            self.docker_client = None
    
    def get_all_namespaces(self) -> List[str]:
        """Get all active namespaces"""
        try:
            namespaces = self.v1.list_namespace()
            return [ns.metadata.name for ns in namespaces.items 
                   if ns.status.phase == "Active" and ns.metadata.name not in self.config.get("exclude_namespaces", [])]
        except Exception as e:
            logger.error(f"Error getting namespaces: {str(e)}")
            return []
    
    def get_images_from_pods(self, namespaces: List[str]) -> Dict[str, ImageInfo]:
        """Get all images used by pods"""
        images = {}
        
        for namespace in namespaces:
            logger.info(f"Scanning pods in namespace: {namespace}")
            
            try:
                # Get all pods in namespace
                pods = self.v1.list_namespaced_pod(namespace)
                
                for pod in pods.items:
                    pod_name = pod.metadata.name
                    
                    # Get images from all containers
                    for container in pod.spec.containers:
                        image_full = container.image
                        image_info = self._parse_image_name(image_full)
                        
                        if image_info.name not in images:
                            images[image_info.name] = image_info
                        else:
                            # Update usage information
                            existing = images[image_info.name]
                            existing.usage_count += 1
                            if pod_name not in existing.pods_using:
                                existing.pods_using.append(pod_name)
                            if namespace not in existing.namespaces_using:
                                existing.namespaces_using.append(namespace)
                            existing.image_pull_policy = container.image_pull_policy
                    
                    # Get images from init containers
                    if pod.spec.init_containers:
                        for container in pod.spec.init_containers:
                            image_full = container.image
                            image_info = self._parse_image_name(image_full)
                            
                            if image_info.name not in images:
                                images[image_info.name] = image_info
                            else:
                                existing = images[image_info.name]
                                existing.usage_count += 1
                                if pod_name not in existing.pods_using:
                                    existing.pods_using.append(pod_name)
                                if namespace not in existing.namespaces_using:
                                    existing.namespaces_using.append(namespace)
                    
            except Exception as e:
                logger.error(f"Error scanning pods in namespace {namespace}: {str(e)}")
        
        return images
    
    def get_images_from_deployments(self, namespaces: List[str]) -> Dict[str, ImageInfo]:
        """Get images from deployments"""
        images = {}
        
        for namespace in namespaces:
            logger.info(f"Scanning deployments in namespace: {namespace}")
            
            try:
                deployments = self.apps_v1.list_namespaced_deployment(namespace)
                
                for deployment in deployments.items:
                    deployment_name = deployment.metadata.name
                    
                    for container in deployment.spec.template.spec.containers:
                        image_full = container.image
                        image_info = self._parse_image_name(image_full)
                        
                        if image_info.name not in images:
                            images[image_info.name] = image_info
                        
                        # Update deployment usage
                        existing = images[image_info.name]
                        if deployment_name not in existing.pods_using:
                            existing.pods_using.append(f"deployment/{deployment_name}")
                        if namespace not in existing.namespaces_using:
                            existing.namespaces_using.append(namespace)
                    
            except Exception as e:
                logger.error(f"Error scanning deployments in namespace {namespace}: {str(e)}")
        
        return images
    
    def get_images_from_daemonsets(self, namespaces: List[str]) -> Dict[str, ImageInfo]:
        """Get images from daemonsets"""
        images = {}
        
        for namespace in namespaces:
            logger.info(f"Scanning daemonsets in namespace: {namespace}")
            
            try:
                daemonsets = self.apps_v1.list_namespaced_daemon_set(namespace)
                
                for daemonset in daemonsets.items:
                    daemonset_name = daemonset.metadata.name
                    
                    for container in daemonset.spec.template.spec.containers:
                        image_full = container.image
                        image_info = self._parse_image_name(image_full)
                        
                        if image_info.name not in images:
                            images[image_info.name] = image_info
                        
                        existing = images[image_info.name]
                        if daemonset_name not in existing.pods_using:
                            existing.pods_using.append(f"daemonset/{daemonset_name}")
                        if namespace not in existing.namespaces_using:
                            existing.namespaces_using.append(namespace)
                    
            except Exception as e:
                logger.error(f"Error scanning daemonsets in namespace {namespace}: {str(e)}")
        
        return images
    
    def get_images_from_statefulsets(self, namespaces: List[str]) -> Dict[str, ImageInfo]:
        """Get images from statefulsets"""
        images = {}
        
        for namespace in namespaces:
            logger.info(f"Scanning statefulsets in namespace: {namespace}")
            
            try:
                statefulsets = self.apps_v1.list_namespaced_stateful_set(namespace)
                
                for statefulset in statefulsets.items:
                    statefulset_name = statefulset.metadata.name
                    
                    for container in statefulset.spec.template.spec.containers:
                        image_full = container.image
                        image_info = self._parse_image_name(image_full)
                        
                        if image_info.name not in images:
                            images[image_info.name] = image_info
                        
                        existing = images[image_info.name]
                        if statefulset_name not in existing.pods_using:
                            existing.pods_using.append(f"statefulset/{statefulset_name}")
                        if namespace not in existing.namespaces_using:
                            existing.namespaces_using.append(namespace)
                    
            except Exception as e:
                logger.error(f"Error scanning statefulsets in namespace {namespace}: {str(e)}")
        
        return images
    
    def get_images_from_cronjobs(self, namespaces: List[str]) -> Dict[str, ImageInfo]:
        """Get images from cronjobs"""
        images = {}
        
        for namespace in namespaces:
            logger.info(f"Scanning cronjobs in namespace: {namespace}")
            
            try:
                batch_v1 = client.BatchV1Api()
                cronjobs = batch_v1.list_namespaced_cron_job(namespace)
                
                for cronjob in cronjobs.items:
                    cronjob_name = cronjob.metadata.name
                    
                    for container in cronjob.spec.job_template.spec.template.spec.containers:
                        image_full = container.image
                        image_info = self._parse_image_name(image_full)
                        
                        if image_info.name not in images:
                            images[image_info.name] = image_info
                        
                        existing = images[image_info.name]
                        if cronjob_name not in existing.pods_using:
                            existing.pods_using.append(f"cronjob/{cronjob_name}")
                        if namespace not in existing.namespaces_using:
                            existing.namespaces_using.append(namespace)
                    
            except Exception as e:
                logger.error(f"Error scanning cronjobs in namespace {namespace}: {str(e)}")
        
        return images
    
    def _parse_image_name(self, image_full: str) -> ImageInfo:
        """Parse image name into components"""
        # Handle different image formats
        if '@' in image_full:
            # Image with digest
            name_part, digest = image_full.split('@', 1)
            tag = 'latest'
        elif ':' in image_full:
            # Image with tag
            name_part, tag = image_full.rsplit(':', 1)
            digest = None
        else:
            # Image without tag (defaults to latest)
            name_part = image_full
            tag = 'latest'
            digest = None
        
        # Extract repository
        if '/' in name_part:
            if name_part.count('/') >= 2 or '.' in name_part.split('/')[0]:
                # Full registry path
                repository = '/'.join(name_part.split('/')[:-1])
                name = name_part.split('/')[-1]
            else:
                # Simple namespace/name format
                repository = name_part.split('/')[0]
                name = name_part.split('/')[-1]
        else:
            repository = 'library'
            name = name_part
        
        return ImageInfo(
            name=name,
            tag=tag,
            repository=repository,
            digest=digest,
            usage_count=1,
            pods_using=[],
            namespaces_using=[]
        )
    
    def get_local_docker_images(self) -> Dict[str, ImageInfo]:
        """Get images from local Docker daemon"""
        if not self.docker_client:
            logger.warning("Docker client not available, skipping local image scan")
            return {}
        
        images = {}
        
        try:
            docker_images = self.docker_client.images.list()
            
            for docker_image in docker_images:
                for tag in docker_image.tags:
                    image_info = self._parse_image_name(tag)
                    
                    # Get image details
                    if hasattr(docker_image, 'attrs') and docker_image.attrs:
                        image_info.size_mb = docker_image.attrs.get('Size', 0) / (1024 * 1024)
                        image_info.created_at = docker_image.attrs.get('Created', '')
                    
                    images[image_info.name] = image_info
        
        except Exception as e:
            logger.error(f"Error getting local Docker images: {str(e)}")
        
        return images
    
    def identify_unused_images(self, k8s_images: Dict[str, ImageInfo], 
                            local_images: Dict[str, ImageInfo]) -> List[ImageInfo]:
        """Identify unused images"""
        unused_images = []
        
        for image_name, local_image in local_images.items():
            # Check if image is used in Kubernetes
            if image_name not in k8s_images:
                # Check exclusions
                if not self._should_exclude_image(local_image):
                    unused_images.append(local_image)
            else:
                # Image is used, update last_used timestamp
                k8s_image = k8s_images[image_name]
                local_image.last_used = datetime.now().isoformat()
                local_image.usage_count = k8s_image.usage_count
                local_image.pods_using = k8s_image.pods_using
                local_image.namespaces_using = k8s_image.namespaces_using
        
        return unused_images
    
    def _should_exclude_image(self, image: ImageInfo) -> bool:
        """Check if image should be excluded from cleanup"""
        # Check system images
        if not self.config.get("include_system_images", False):
            system_patterns = ['k8s.gcr.io', 'kubernetes', 'gcr.io/k8s-']
            for pattern in system_patterns:
                if pattern in image.repository:
                    return True
        
        # Check explicit exclusions
        exclude_images = self.config.get("exclude_images", [])
        for exclude_pattern in exclude_images:
            if exclude_pattern in f"{image.repository}/{image.name}":
                return True
        
        # Check recent images (within retention period)
        if image.created_at:
            try:
                created_date = datetime.fromisoformat(image.created_at.replace('Z', '+00:00'))
                retention_days = self.config.get("retention_days", 30)
                if datetime.now(created_date.tzinfo) - created_date < timedelta(days=retention_days):
                    return True
            except:
                pass
        
        return False
    
    def get_image_size_from_registry(self, image: ImageInfo) -> Optional[float]:
        """Get image size from registry (if available)"""
        if not self.config.get("docker_registry", {}).get("check_registry", False):
            return None
        
        try:
            # This is a simplified version - actual implementation would depend on registry type
            # For Docker Hub, you could use the API
            if 'docker.io' in image.repository or image.repository == 'library':
                return self._get_docker_hub_image_size(image)
            
        except Exception as e:
            logger.debug(f"Could not get size from registry for {image.name}: {str(e)}")
        
        return None
    
    def _get_docker_hub_image_size(self, image: ImageInfo) -> Optional[float]:
        """Get image size from Docker Hub API"""
        try:
            # Docker Hub API endpoint
            url = f"https://registry.hub.docker.com/v2/repositories/{image.repository}/{image.name}/tags/{image.tag}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                # Size is in bytes, convert to MB
                size_bytes = data.get('full_size', 0)
                return size_bytes / (1024 * 1024)
        
        except Exception as e:
            logger.debug(f"Docker Hub API error: {str(e)}")
        
        return None
    
    def generate_recommendations(self, unused_images: List[ImageInfo]) -> List[str]:
        """Generate cleanup recommendations"""
        recommendations = []
        
        if not unused_images:
            recommendations.append("No unused images found. Cluster is optimized!")
            return recommendations
        
        total_size = sum(img.size_mb or 0 for img in unused_images)
        
        recommendations.append(f"Found {len(unused_images)} unused images consuming {total_size:.2f} MB of storage")
        
        # Size-based recommendations
        large_images = [img for img in unused_images if (img.size_mb or 0) > 500]
        if large_images:
            recommendations.append(f"Priority cleanup: {len(large_images)} large images (>500MB) identified")
        
        # Age-based recommendations
        old_images = [img for img in unused_images if img.created_at]
        if old_images:
            recommendations.append("Consider implementing automated image cleanup policies")
        
        # Registry recommendations
        recommendations.append("Use image pull policy 'IfNotPresent' to reduce unnecessary downloads")
        recommendations.append("Implement image tagging strategy for better lifecycle management")
        recommendations.append("Consider using image scanning and vulnerability assessment tools")
        
        return recommendations
    
    def generate_report(self, k8s_images: Dict[str, ImageInfo], 
                       local_images: Dict[str, ImageInfo], 
                       unused_images: List[ImageInfo]) -> UnusedImageReport:
        """Generate comprehensive report"""
        total_images = len(local_images)
        used_images = len(k8s_images)
        unused_count = len(unused_images)
        
        potential_savings = sum(img.size_mb or 0 for img in unused_images)
        
        # Usage statistics
        usage_stats = {
            "total_images": total_images,
            "used_images": used_images,
            "unused_images": unused_count,
            "potential_savings_mb": potential_savings,
            "images_by_repository": dict(Counter(img.repository for img in local_images.values())),
            "largest_unused_images": sorted(
                [(img.name, img.size_mb or 0) for img in unused_images], 
                key=lambda x: x[1], reverse=True
            )[:10]
        }
        
        recommendations = self.generate_recommendations(unused_images)
        
        return UnusedImageReport(
            timestamp=datetime.now().isoformat(),
            total_images=total_images,
            used_images=used_images,
            unused_images=unused_count,
            potential_savings_mb=potential_savings,
            unused_images_details=unused_images,
            usage_statistics=usage_stats,
            recommendations=recommendations
        )
    
    def save_report(self, report: UnusedImageReport, output_formats: List[str]):
        """Save report in specified formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if 'json' in output_formats:
            json_file = f"unused_images_report_{timestamp}.json"
            with open(json_file, 'w') as f:
                json.dump(asdict(report), f, indent=2, default=str)
            logger.info(f"JSON report saved to: {json_file}")
        
        if 'csv' in output_formats:
            csv_file = f"unused_images_report_{timestamp}.csv"
            df = pd.DataFrame([asdict(img) for img in report.unused_images_details])
            df.to_csv(csv_file, index=False)
            logger.info(f"CSV report saved to: {csv_file}")
        
        if 'html' in output_formats:
            html_file = f"unused_images_report_{timestamp}.html"
            self._generate_html_report(report, html_file)
            logger.info(f"HTML report saved to: {html_file}")
    
    def _generate_html_report(self, report: UnusedImageReport, filename: str):
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Unused Images Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .summary-item {{ text-align: center; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .unused {{ background-color: #f8d7da; }}
                .used {{ background-color: #d4edda; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .recommendations {{ background-color: #fff3cd; padding: 15px; border-radius: 5px; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Unused Images Report</h1>
                <p>Generated on: {report.timestamp}</p>
            </div>
            
            <div class="summary">
                <div class="summary-item">
                    <h3>{report.total_images}</h3>
                    <p>Total Images</p>
                </div>
                <div class="summary-item used">
                    <h3>{report.used_images}</h3>
                    <p>Used Images</p>
                </div>
                <div class="summary-item unused">
                    <h3>{report.unused_images}</h3>
                    <p>Unused Images</p>
                </div>
                <div class="summary-item">
                    <h3>{report.potential_savings_mb:.2f} MB</h3>
                    <p>Potential Savings</p>
                </div>
            </div>
            
            <h2>Unused Images Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Image Name</th>
                        <th>Tag</th>
                        <th>Repository</th>
                        <th>Size (MB)</th>
                        <th>Created At</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for img in report.unused_images_details:
            html_content += f"""
                    <tr>
                        <td>{img.name}</td>
                        <td>{img.tag}</td>
                        <td>{img.repository}</td>
                        <td>{img.size_mb or 'N/A'}</td>
                        <td>{img.created_at or 'N/A'}</td>
                    </tr>
            """
        
        html_content += """
                </tbody>
            </table>
            
            <div class="recommendations">
                <h2>Recommendations</h2>
                <ul>
        """
        
        for rec in report.recommendations:
            html_content += f"<li>{rec}</li>"
        
        html_content += """
                </ul>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
    
    def run_detection(self) -> UnusedImageReport:
        """Run the complete detection process"""
        logger.info("Starting unused images detection...")
        
        # Get namespaces to scan
        namespaces = self.config.get("namespaces", [])
        if not namespaces or "all" in namespaces:
            namespaces = self.get_all_namespaces()
        
        logger.info(f"Scanning namespaces: {namespaces}")
        
        # Get images from Kubernetes resources
        k8s_images = {}
        k8s_images.update(self.get_images_from_pods(namespaces))
        k8s_images.update(self.get_images_from_deployments(namespaces))
        k8s_images.update(self.get_images_from_daemonsets(namespaces))
        k8s_images.update(self.get_images_from_statefulsets(namespaces))
        k8s_images.update(self.get_images_from_cronjobs(namespaces))
        
        logger.info(f"Found {len(k8s_images)} unique images in Kubernetes")
        
        # Get local Docker images
        local_images = self.get_local_docker_images()
        logger.info(f"Found {len(local_images)} local Docker images")
        
        # Identify unused images
        unused_images = self.identify_unused_images(k8s_images, local_images)
        logger.info(f"Identified {len(unused_images)} unused images")
        
        # Generate report
        report = self.generate_report(k8s_images, local_images, unused_images)
        
        return report

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Detect unused container images')
    parser.add_argument('--config', type=str, default='config/image_detection_config.json', 
                       help='Configuration file path')
    parser.add_argument('--output-format', nargs='+', default=['json', 'csv'], 
                       choices=['json', 'csv', 'html'], help='Output formats')
    parser.add_argument('--namespaces', nargs='+', help='Specific namespaces to scan')
    
    args = parser.parse_args()
    
    try:
        detector = UnusedImagesDetector(args.config)
        
        # Override namespaces if provided
        if args.namespaces:
            detector.config["namespaces"] = args.namespaces
        
        # Run detection
        report = detector.run_detection()
        
        # Save report
        detector.save_report(report, args.output_format)
        
        # Print summary
        print(f"\n=== Unused Images Detection Summary ===")
        print(f"Total images: {report.total_images}")
        print(f"Used images: {report.used_images}")
        print(f"Unused images: {report.unused_images}")
        print(f"Potential savings: {report.potential_savings_mb:.2f} MB")
        
        if report.recommendations:
            print(f"\n=== Recommendations ===")
            for i, rec in enumerate(report.recommendations, 1):
                print(f"{i}. {rec}")
        
        logger.info("Unused images detection completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during unused images detection: {str(e)}")
        raise

if __name__ == "__main__":
    main()
