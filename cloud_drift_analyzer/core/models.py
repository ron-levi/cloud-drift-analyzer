from enum import Enum
from typing import Dict, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field


class DriftType(str, Enum):
    """Enum representing different types of infrastructure drift."""
    MISSING = "MISSING"  # Resource exists in IaC but not in cloud
    CHANGED = "CHANGED"  # Resource exists in both but has differences
    EXTRA = "EXTRA"      # Resource exists in cloud but not in IaC


class ResourceState(BaseModel):
    """Represents the state of a cloud resource."""
    resource_id: str
    resource_type: str
    provider: str
    properties: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None


class DriftResult(BaseModel):
    """Represents the result of a drift analysis."""
    drift_type: DriftType
    resource: ResourceState
    expected_state: Optional[ResourceState] = None
    actual_state: Optional[ResourceState] = None
    changes: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow)

    def has_drift(self) -> bool:
        """Check if there is any drift detected."""
        return True if self.drift_type in [DriftType.MISSING, DriftType.CHANGED, DriftType.EXTRA] else False

    def get_drift_summary(self) -> Dict[str, Any]:
        """Generate a summary of the drift detection."""
        return {
            "drift_type": self.drift_type.value,
            "resource_id": self.resource.resource_id,
            "resource_type": self.resource.resource_type,
            "provider": self.resource.provider,
            "changes": self.changes,
            "timestamp": self.timestamp
        }