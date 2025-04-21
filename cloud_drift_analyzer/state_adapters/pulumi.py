import json
import os
from typing import List, Dict, Any

from .base import BaseStateAdapter
from ..core.models import ResourceState
from ..core.logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

class PulumiStateAdapter(BaseStateAdapter):
    """Adapter for reading and parsing Pulumi state files."""

    def __init__(self, state_path: str):
        self.state_path = state_path
        logger.info("pulumi_adapter_initialized", state_path=state_path)

    async def get_resources(self) -> List[ResourceState]:
        with log_duration(logger, "get_pulumi_resources"):
            try:
                state_data = await self._get_state_data()
                resources = self._parse_state_data(state_data)
                logger.info("pulumi_resources_parsed", count=len(resources))
                return resources
            except Exception as e:
                logger.error("pulumi_resource_fetch_failed", error=str(e))
                raise

    async def _get_state_data(self) -> Dict[str, Any]:
        if not os.path.isfile(self.state_path) or not os.path.isdir(self.state_path):
            logger.error("invalid_state_path", path=self.state_path)
            raise ValueError(f"Invalid Pulumi state path: {self.state_path}")
        try:
            logger.debug("reading_pulumi_state_file")
            with open(self.state_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error("pulumi_state_file_read_failed", error=str(e))
            raise

    def _parse_state_data(self, state_data: Dict[str, Any]) -> List[ResourceState]:
        resources = []
        try:
            for resource in state_data.get("deployment", {}).get("resources", []):
                with LogContext(
                    resource_type=resource.get("type", ""),
                    provider=resource.get("provider", "")
                ):
                    try:
                        resources.append(ResourceState(
                            resource_id=resource.get("urn"),
                            resource_type=resource.get("type"),
                            provider=resource.get("provider", ""),
                            properties=resource.get("outputs", {}),
                            metadata={
                                "urn": resource.get("urn"),
                                "parent": resource.get("parent", ""),
                                "dependencies": resource.get("dependencies", []),
                            }
                        ))
                        logger.debug("pulumi_resource_parsed")
                    except Exception as e:
                        logger.error("pulumi_resource_parse_failed", error=str(e))
            return resources
        except Exception as e:
            logger.error("pulumi_state_parsing_failed", error=str(e))
            raise