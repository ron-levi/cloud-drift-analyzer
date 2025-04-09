from abc import ABC, abstractmethod
from typing import Dict, List, Any

class CloudProvider(ABC):
    """Abstract base class for cloud providers to implement resource state retrieval."""

    def __init__(self, credentials: Dict[str, Any]):
        self.credentials = credentials

    @abstractmethod
    def get_resources(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Retrieve all resources from the cloud provider.
        
        Returns:
            Dict mapping resource types to lists of resource details
        """  

    @abstractmethod
    def get_resource_by_id(self, resource_type: str, resource_id: str) -> Dict[str, Any]:
        """
        Retrieve a specific resource by its ID.
        
        Args:
            resource_type: Type of resource (e.g., 'vm', 'storage', 'network')
            resource_id: Unique identifier of the resource
            
        Returns:
            Resource details as a dictionary
        """

    @abstractmethod
    def get_resource_types(self) -> List[str]:
        """
        Get list of supported resource types.
        
        Returns:
            List of resource type strings
        """

    @abstractmethod
    def authenticate(self) -> bool:
        """
        Authenticate with the cloud provider.
        
        Returns:
            True if authentication successful, False otherwise
        """