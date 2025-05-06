from typing import Dict, List, Any, Optional
import json
import subprocess
import os
from datetime import datetime

from .base import BaseStateAdapter
from ..core.models import ResourceState
from ..core.logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

class PulumiStateError(Exception):
    """Base exception for Pulumi state errors."""
    pass

class PulumiStateAdapter(BaseStateAdapter):
    """Adapter for reading and parsing Pulumi state."""

    def __init__(self, stack_name: str, project_path: Optional[str] = None):
        """
        Initialize Pulumi state adapter.
        
        Args:
            stack_name: Name of the Pulumi stack (e.g., 'dev', 'prod')
            project_path: Optional path to Pulumi project directory
        """
        self.stack_name = stack_name
        self.project_path = project_path or os.getcwd()
        logger.info("pulumi_adapter_initialized", 
                   stack_name=stack_name,
                   project_path=self.project_path)

    async def validate_state_file(self) -> bool:
        """Validate Pulumi state and project configuration."""
        try:
            # Check if Pulumi project exists
            if not os.path.exists(os.path.join(self.project_path, "Pulumi.yaml")):
                logger.error("pulumi_project_not_found",
                           path=self.project_path)
                return False

            # Verify stack exists and is accessible
            result = subprocess.run(
                ["pulumi", "stack", "ls"],
                cwd=self.project_path,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.error("pulumi_stack_list_failed",
                           error=result.stderr)
                return False

            if self.stack_name not in result.stdout:
                logger.error("stack_not_found",
                           stack_name=self.stack_name)
                return False

            # Verify stack has resources
            stack_info = await self._get_stack_info()
            if not stack_info.get('deployment', {}).get('resources'):
                logger.warning("empty_stack",
                             stack_name=self.stack_name)
                return True  # Empty stack is still valid

            return True

        except Exception as e:
            logger.error("state_validation_failed",
                        error=str(e))
            return False

    async def get_state_metadata(self) -> Dict[str, Any]:
        """Get metadata about the Pulumi stack state."""
        try:
            stack_info = await self._get_stack_info()
            config = await self._get_stack_config()

            return {
                'stack_name': self.stack_name,
                'last_update': stack_info.get('deployment', {}).get('timestamp', ''),
                'version': stack_info.get('version', ''),
                'resource_count': len(stack_info.get('deployment', {}).get('resources', [])),
                'config': config,
                'tags': stack_info.get('tags', {}),
                'backend_url': stack_info.get('backend_url', '')
            }

        except Exception as e:
            logger.error("metadata_fetch_failed",
                        error=str(e))
            raise PulumiStateError(f"Failed to get stack metadata: {str(e)}")

    async def get_resources(self) -> List[ResourceState]:
        """Get resources from Pulumi stack state."""
        with log_duration(logger, "get_pulumi_resources"):
            try:
                # Validate state before proceeding
                if not await self.validate_state_file():
                    raise PulumiStateError("Invalid or inaccessible Pulumi state")

                stack_info = await self._get_stack_info()
                resources = await self._parse_stack_resources(stack_info)
                
                logger.info("pulumi_resources_parsed",
                          count=len(resources))
                return resources

            except subprocess.CalledProcessError as e:
                logger.error("pulumi_command_failed",
                           error=str(e))
                raise PulumiStateError(f"Pulumi command failed: {str(e)}")
            except json.JSONDecodeError as e:
                logger.error("pulumi_state_parse_failed",
                           error=str(e))
                raise PulumiStateError(f"Invalid JSON in Pulumi state: {str(e)}")
            except Exception as e:
                logger.error("pulumi_resource_fetch_failed",
                           error=str(e))
                raise

    async def _get_stack_info(self) -> Dict[str, Any]:
        """Get Pulumi stack information."""
        try:
            result = subprocess.run(
                ["pulumi", "stack", "export", "--stack", self.stack_name],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error("stack_export_failed",
                        error=e.stderr)
            raise
        except json.JSONDecodeError as e:
            logger.error("stack_export_parse_failed",
                        error=str(e))
            raise

    async def _get_stack_config(self) -> Dict[str, Any]:
        """Get Pulumi stack configuration."""
        try:
            result = subprocess.run(
                ["pulumi", "config", "--show-secrets", "--json"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error("config_fetch_failed",
                        error=e.stderr)
            raise
        except json.JSONDecodeError as e:
            logger.error("config_parse_failed",
                        error=str(e))
            raise

    async def _parse_stack_resources(self, stack_info: Dict[str, Any]) -> List[ResourceState]:
        """Parse Pulumi stack resources into ResourceState objects."""
        resources = []
        
        try:
            deployment = stack_info.get('deployment', {})
            for resource in deployment.get('resources', []):
                with LogContext(
                    resource_type=resource.get('type', ''),
                    provider=self._extract_provider(resource.get('type', ''))
                ):
                    try:
                        # Skip providers and component resources
                        if resource.get('type', '').endswith('::Provider') or \
                           resource.get('custom', True) is False:
                            continue

                        provider = self._extract_provider(resource['type'])
                        resources.append(ResourceState(
                            resource_id=resource.get('id', ''),
                            resource_type=resource['type'],
                            provider=provider,
                            properties=resource.get('outputs', {}),
                            metadata={
                                'urn': resource.get('urn', ''),
                                'parent': resource.get('parent', ''),
                                'protect': resource.get('protect', False),
                                'custom': resource.get('custom', True),
                                'dependencies': resource.get('dependencies', [])
                            }
                        ))
                        logger.debug("resource_parsed")
                    except Exception as e:
                        logger.error("resource_parse_failed",
                                   urn=resource.get('urn', ''),
                                   error=str(e))

            return resources

        except Exception as e:
            logger.error("stack_parsing_failed",
                        error=str(e))
            raise

    def _extract_provider(self, resource_type: str) -> str:
        """Extract provider name from resource type."""
        try:
            return resource_type.split(':')[0].lower()
        except Exception:
            return "unknown"

    async def get_resource(self, resource_id: str) -> Optional[ResourceState]:
        """Get a specific resource by ID."""
        try:
            stack_info = await self._get_stack_info()
            deployment = stack_info.get('deployment', {})
            
            for resource in deployment.get('resources', []):
                if resource.get('id') == resource_id:
                    provider = self._extract_provider(resource['type'])
                    return ResourceState(
                        resource_id=resource_id,
                        resource_type=resource['type'],
                        provider=provider,
                        properties=resource.get('outputs', {}),
                        metadata={
                            'urn': resource.get('urn', ''),
                            'parent': resource.get('parent', ''),
                            'protect': resource.get('protect', False),
                            'custom': resource.get('custom', True),
                            'dependencies': resource.get('dependencies', [])
                        }
                    )
            
            logger.warning("resource_not_found",
                         resource_id=resource_id)
            return None
            
        except Exception as e:
            logger.error("resource_fetch_failed",
                        resource_id=resource_id,
                        error=str(e))
            raise PulumiStateError(f"Failed to fetch resource {resource_id}: {str(e)}")

    async def refresh_state(self) -> bool:
        """Refresh the Pulumi stack state."""
        try:
            result = subprocess.run(
                ["pulumi", "refresh", "--stack", self.stack_name, "--yes"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("state_refreshed",
                       stack_name=self.stack_name)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("state_refresh_failed",
                        error=e.stderr)
            return False
        except Exception as e:
            logger.error("state_refresh_error",
                        error=str(e))
            return False