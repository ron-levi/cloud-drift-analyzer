import json
import os
from typing import List, Dict, Any
import subprocess
import glob
from datetime import datetime

from .base import BaseStateAdapter
from ..core.models import ResourceState
from ..core.logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

class TerraformStateAdapter(BaseStateAdapter):
    """Adapter for reading and parsing Terraform state."""
    
    def __init__(self, state_path: str):
        """Initialize the adapter with path to state file or directory."""
        self.state_path = state_path
        logger.info("terraform_adapter_initialized", state_path=state_path)
        
    async def get_resources(self) -> List[ResourceState]:
        """Get resources from Terraform state."""
        with log_duration(logger, "get_terraform_resources"):
            if not await self.validate_state_file():
                raise ValueError("Invalid or corrupted Terraform state")
            state_data = await self._get_state_data()
            return self._parse_state_data(state_data)

    async def validate_state_file(self) -> bool:
        """Validate the Terraform state file format."""
        try:
            if os.path.isfile(self.state_path) and self.state_path.endswith('.tfstate'):
                with open(self.state_path, 'r') as f:
                    state_data = json.load(f)
                
                # Validate required fields
                required_fields = ['version', 'terraform_version', 'serial', 'lineage', 'resources']
                missing_fields = [field for field in required_fields if field not in state_data]
                
                if missing_fields:
                    logger.error("invalid_state_file", 
                               missing_fields=missing_fields)
                    return False
                
                # Validate version compatibility
                if state_data['version'] not in [3, 4]:  # Current supported versions
                    logger.error("unsupported_state_version",
                               version=state_data['version'])
                    return False
                
                return True
                
            elif os.path.isdir(self.state_path):
                # Check for terraform init capability
                if not os.path.exists(os.path.join(self.state_path, '.terraform')):
                    result = subprocess.run(
                        ['terraform', 'init', '-backend=false'],
                        cwd=self.state_path,
                        capture_output=True,
                        text=True
                    )
                    if result.returncode != 0:
                        logger.error("terraform_init_failed",
                                   error=result.stderr)
                        return False
                
                # Verify terraform files exist
                tf_files = glob.glob(os.path.join(self.state_path, '*.tf'))
                if not tf_files:
                    logger.error("no_terraform_files_found",
                               path=self.state_path)
                    return False
                
                return True
            
            return False
            
        except Exception as e:
            logger.error("state_validation_failed", 
                        error=str(e))
            return False

    async def get_state_metadata(self) -> Dict[str, Any]:
        """Get metadata about the state file."""
        try:
            if os.path.isfile(self.state_path) and self.state_path.endswith('.tfstate'):
                with open(self.state_path, 'r') as f:
                    state_data = json.load(f)
                return {
                    'version': state_data.get('version'),
                    'terraform_version': state_data.get('terraform_version'),
                    'serial': state_data.get('serial'),
                    'lineage': state_data.get('lineage'),
                    'backend': state_data.get('backend', {}),
                    'resource_count': len(state_data.get('resources', [])),
                    'last_modified': datetime.fromtimestamp(os.path.getmtime(self.state_path)).isoformat()
                }
            elif os.path.isdir(self.state_path):
                # Get workspace info
                workspace_cmd = subprocess.run(
                    ['terraform', 'workspace', 'show'],
                    cwd=self.state_path,
                    capture_output=True,
                    text=True
                )
                
                # Get backend config
                config_files = glob.glob(os.path.join(self.state_path, '*.tf'))
                backend_config = {}
                for file in config_files:
                    with open(file, 'r') as f:
                        content = f.read()
                        if 'backend' in content:
                            backend_config['file'] = os.path.basename(file)
                            break
                
                return {
                    'workspace': workspace_cmd.stdout.strip() if workspace_cmd.returncode == 0 else 'default',
                    'backend_config': backend_config,
                    'config_files': [os.path.basename(f) for f in config_files],
                    'last_modified': datetime.fromtimestamp(max(os.path.getmtime(f) for f in config_files)).isoformat()
                }
                
            raise ValueError(f"Invalid state path: {self.state_path}")
            
        except Exception as e:
            logger.error("metadata_fetch_failed", 
                        error=str(e))
            raise

    async def _get_state_data(self) -> Dict[str, Any]:
        """Get Terraform state data from file or by running terraform show."""
        if os.path.isfile(self.state_path) and self.state_path.endswith('.tfstate'):
            try:
                logger.debug("reading_tfstate_file")
                with open(self.state_path, 'r') as f:
                    data = json.load(f)
                logger.debug("tfstate_file_read")
                return data
            except Exception as e:
                logger.error("tfstate_file_read_failed", 
                           error=str(e))
                raise
        elif os.path.isdir(self.state_path):
            return await self._get_state_from_terraform()
        else:
            logger.error("invalid_state_path", path=self.state_path)
            raise ValueError(f"Invalid state path: {self.state_path}")
            
    async def _get_state_from_terraform(self) -> Dict[str, Any]:
        """Run terraform commands to get state data."""
        # Change to the terraform directory
        orig_dir = os.getcwd()
        os.chdir(self.state_path)
        
        try:
            with log_duration(logger, "terraform_operations"):
                # Initialize Terraform
                logger.debug("initializing_terraform")
                init_result = subprocess.run(
                    ['terraform', 'init'],
                    check=True,
                    capture_output=True
                )
                logger.debug("terraform_initialized")
                
                # Get the state in JSON format
                logger.debug("fetching_terraform_state")
                show_result = subprocess.run(
                    ['terraform', 'show', '-json'],
                    check=True,
                    capture_output=True,
                    text=True
                )
                logger.debug("terraform_state_fetched")
                
                return json.loads(show_result.stdout)
                
        except subprocess.CalledProcessError as e:
            logger.error("terraform_command_failed",
                        command=e.cmd,
                        returncode=e.returncode,
                        stdout=e.stdout,
                        stderr=e.stderr)
            raise
        except json.JSONDecodeError as e:
            logger.error("terraform_state_parse_failed",
                        error=str(e))
            raise
        except Exception as e:
            logger.error("terraform_state_fetch_failed",
                        error=str(e))
            raise
        finally:
            # Change back to original directory
            os.chdir(orig_dir)
            
    def _parse_state_data(self, state_data: Dict[str, Any]) -> List[ResourceState]:
        """Parse Terraform state data into ResourceState objects."""
        # Handle both tfstate file format and terraform show -json format
        if 'values' in state_data:
            root_module = state_data['values'].get('root_module', {})
            resources = self._parse_module_resources(root_module)
            for module in root_module.get('child_modules', []):
                resources.extend(self._parse_module_resources(module))
            return resources
        elif 'resources' in state_data:
            return [r for resource in state_data['resources'] for r in self._parse_tfstate_resource(resource)]
        return []

    def _parse_module_resources(self, module: Dict[str, Any]) -> List[ResourceState]:
        """Parse resources from a module in terraform show -json format."""
        provider = lambda r: r.get('provider_name', '')
        resource_type = lambda r: r.get('type', '')
        return [
            ResourceState(
                resource_id=instance.get('index_key', resource.get('name', '')),
                resource_type=f"{provider(resource)}_{resource_type(resource)}",
                provider=provider(resource),
                properties=instance.get('attributes', {}),
                metadata={
                    'address': resource.get('address', ''),
                    'mode': resource.get('mode', '')
                }
            )
            for resource in module.get('resources', [])
            for instance in resource.get('instances', [])
        ]

    def _parse_tfstate_resource(self, resource: Dict[str, Any]) -> List[ResourceState]:
        """Parse a resource from .tfstate format."""
        provider = resource.get('provider', '').split('/')[-1]
        resource_type = resource.get('type', '')
        return [
            ResourceState(
                resource_id=instance.get('index_key', resource.get('name', '')),
                resource_type=resource_type,
                provider=provider,
                properties=instance.get('attributes', {}),
                metadata={
                    'module': resource.get('module', ''),
                    'mode': resource.get('mode', '')
                }
            )
            for instance in resource.get('instances', [])
        ]