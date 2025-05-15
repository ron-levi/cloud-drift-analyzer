from typing import Dict, Any, List
import re
from datetime import datetime
import json

# Removed logger usage from simple utility functions for clarity and performance

def sanitize_resource_id(resource_id: str) -> str:
    """Remove any provider-specific prefixes from resource IDs."""
    prefixes = ['arn:aws:', 'projects/', '/subscriptions/']
    for prefix in prefixes:
        if resource_id.startswith(prefix):
            return resource_id[len(prefix):]
    return resource_id

def format_timestamp(timestamp: datetime) -> str:
    """Format timestamp in ISO 8601 format with timezone."""
    return timestamp.isoformat()

def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """Flatten a nested dictionary using dot notation."""
    items: List = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def normalize_tags(tags: Dict[str, str]) -> Dict[str, str]:
    """Normalize resource tags to a standard format."""
    return {re.sub(r'[^a-zA-Z0-9]', '_', key.lower()): str(value) for key, value in tags.items()}

def parse_resource_type(resource_type: str) -> tuple[str, str]:
    """Parse a resource type into provider and type components."""
    parts = resource_type.split('_', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return 'unknown', resource_type

def safe_json_dumps(obj: Any) -> str:
    """Safely convert an object to JSON string, handling datetime objects."""
    def json_serial(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")
    return json.dumps(obj, default=json_serial, sort_keys=True)

def redact_sensitive_data(data: Dict[str, Any], sensitive_keys: List[str]) -> Dict[str, Any]:
    """Redact sensitive information from a dictionary."""
    return {k: ("**REDACTED**" if k in sensitive_keys else v) for k, v in data.items()}