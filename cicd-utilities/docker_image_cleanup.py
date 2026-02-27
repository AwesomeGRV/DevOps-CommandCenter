#!/usr/bin/env python3
"""
Docker Image Cleanup Script
Author: CloudOps-SRE-Toolkit
Description: Clean up unused and old Docker images to free up disk space
"""

import subprocess
import json
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ImageInfo:
    id: str
    repository: str
    tag: str
    size: str
    created: str
    days_old: int
    used: bool

class DockerImageCleaner:
    def __init__(self, dry_run: bool = False, keep_days: int = 30):
        self.dry_run = dry_run
        self.keep_days = keep_days
    
    def get_images(self) -> List[ImageInfo]:
        images = []
        
        try:
            # Get all images
            result = subprocess.run(
                ["docker", "images", "--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\t')
                    image_id, repository, tag, size, created_str = parts
                    
                    # Calculate age
                    created = datetime.strptime(created_str, '%Y-%m-%d %H:%M:%S %z')
                    days_old = (datetime.now(created.tzinfo) - created).days
                    
                    # Check if image is used by any container
                    used = self._is_image_used(image_id)
                    
                    images.append(ImageInfo(
                        id=image_id,
                        repository=repository,
                        tag=tag,
                        size=size,
                        created=created_str,
                        days_old=days_old,
                        used=used
                    ))
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting Docker images: {str(e)}")
        
        return images
    
    def _is_image_used(self, image_id: str) -> bool:
        try:
            result = subprocess.run(
                ["docker", "ps", "-a", "--filter", f"ancestor={image_id}", "--format", "{{.ID}}"],
                capture_output=True,
                text=True,
                check=True
            )
            return len(result.stdout.strip()) > 0
        except:
            return False
    
    def cleanup_images(self) -> Dict[str, Any]:
        images = self.get_images()
        
        # Identify images to remove
        to_remove = []
        total_size_freed = 0
        
        for image in images:
            should_remove = False
            reason = ""
            
            # Remove unused images older than keep_days
            if not image.used and image.days_old > self.keep_days:
                should_remove = True
                reason = f"Unused for {image.days_old} days"
            
            # Remove dangling images (no repository/tag)
            elif image.repository == "<none>" and image.tag == "<none>":
                should_remove = True
                reason = "Dangling image"
            
            if should_remove:
                to_remove.append({
                    "image": image,
                    "reason": reason
                })
                # Estimate size (convert to bytes for calculation)
                size_str = image.size.replace("MB", "").replace("GB", "").strip()
                if "GB" in image.size:
                    total_size_freed += float(size_str) * 1024
                else:
                    total_size_freed += float(size_str)
        
        # Remove images
        removed_images = []
        failed_removals = []
        
        for item in to_remove:
            image = item["image"]
            reason = item["reason"]
            
            if self.dry_run:
                logger.info(f"DRY RUN: Would remove image {image.repository}:{image.tag} ({reason})")
                removed_images.append({
                    "id": image.id,
                    "repository": image.repository,
                    "tag": image.tag,
                    "reason": reason,
                    "size": image.size
                })
            else:
                try:
                    subprocess.run(
                        ["docker", "rmi", "-f", image.id],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    logger.info(f"Removed image {image.repository}:{image.tag} ({reason})")
                    removed_images.append({
                        "id": image.id,
                        "repository": image.repository,
                        "tag": image.tag,
                        "reason": reason,
                        "size": image.size
                    })
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to remove image {image.id}: {str(e)}")
                    failed_removals.append({
                        "id": image.id,
                        "repository": image.repository,
                        "tag": image.tag,
                        "error": str(e)
                    })
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_images": len(images),
            "images_removed": len(removed_images),
            "failed_removals": len(failed_removals),
            "estimated_size_freed_mb": total_size_freed,
            "dry_run": self.dry_run,
            "removed_images": removed_images,
            "failed_removals": failed_removals
        }

def main():
    parser = argparse.ArgumentParser(description='Clean up Docker images')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be removed without actually removing')
    parser.add_argument('--keep-days', type=int, default=30, help='Keep images newer than this many days')
    parser.add_argument('--output', default='docker_cleanup_report.json')
    
    args = parser.parse_args()
    
    try:
        cleaner = DockerImageCleaner(dry_run=args.dry_run, keep_days=args.keep_days)
        report = cleaner.cleanup_images()
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Docker Cleanup Summary:")
        print(f"Total images: {report['total_images']}")
        print(f"Images removed: {report['images_removed']}")
        print(f"Failed removals: {report['failed_removals']}")
        print(f"Size freed: {report['estimated_size_freed_mb']:.1f} MB")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
