from abc import ABC, abstractmethod
from typing import List

from ..core.models import ResourceState

class BaseStateAdapter(ABC):
    """Base class for all state adapters that parse infrastructure state files."""
    
    def __init__(self, state_path: str):
        """Initialize the state adapter with a path to state file or directory.
        
        Args:
            state_path: Path to either a state file or directory containing state files
        """
        self.state_path = state_path
    
    @abstractmethod
    async def get_resources(self) -> List[ResourceState]:
        """Get list of resources from the state.
        
        Returns:
            List of ResourceState objects representing infrastructure resources
        """
        pass