from typing import Dict, Any, List
import re
from datetime import datetime
import json
from .logging import get_logger, LogContext

logger = get_logger(__name__)

def sanitize_resource_id(resource_id: str) -> str:
    """Remove any provider-specific prefixes from resource IDs."""
    logger.debug("sanitizing_resource_id", original_id=resource_id)
    
    # Remove common cloud provider prefixes
    prefixes = ['arn:aws:', 'projects/', '/subscriptions/']
    for prefix in prefixes:
        if resource_id.startswith(prefix):
            resource_id = resource_id[len(prefix):]
            logger.debug("prefix_removed",
                        prefix=prefix,
                        result=resource_id)
            break
    return resource_id

def format_timestamp(timestamp: datetime) -> str:
    """Format timestamp in ISO 8601 format with timezone."""
    try:
        formatted = timestamp.isoformat()
        logger.debug("timestamp_formatted",
                    original=str(timestamp),
                    formatted=formatted)
        return formatted
    except Exception as e:
        logger.error("timestamp_format_failed",
                    error=str(e))
        raise

def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """Flatten a nested dictionary using dot notation."""
    try:
        items: List = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        
        result = dict(items)
        logger.debug("dict_flattened",
                    original_keys=len(d),
                    flattened_keys=len(result))
        return result
        
    except Exception as e:
        logger.error("dict_flatten_failed",
                    error=str(e))
        raise

def normalize_tags(tags: Dict[str, str]) -> Dict[str, str]:
    """Normalize resource tags to a standard format."""
    try:
        normalized = {}
        for key, value in tags.items():
            # Convert to lowercase and replace special characters
            norm_key = re.sub(r'[^a-zA-Z0-9]', '_', key.lower())
            normalized[norm_key] = str(value)
            
        logger.debug("tags_normalized",
                    original_count=len(tags),
                    normalized_count=len(normalized))
        return normalized
        
    except Exception as e:
        logger.error("tag_normalization_failed",
                    error=str(e),
                    tags=tags)
        raise

def parse_resource_type(resource_type: str) -> tuple[str, str]:
    """Parse a resource type into provider and type components."""
    try:
        # Example: aws_s3_bucket -> (aws, s3_bucket)
        parts = resource_type.split('_', 1)
        if len(parts) == 2:
            logger.debug("resource_type_parsed",
                        original=resource_type,
                        provider=parts[0],
                        type=parts[1])
            return parts[0], parts[1]
            
        logger.warning("resource_type_parse_failed",
                      resource_type=resource_type)
        return 'unknown', resource_type
        
    except Exception as e:
        logger.error("resource_type_parse_error",
                    error=str(e),
                    resource_type=resource_type)
        return 'unknown', resource_type

def safe_json_dumps(obj: Any) -> str:
    """Safely convert an object to JSON string, handling datetime objects."""
    try:
        def json_serial(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
        
        result = json.dumps(obj, default=json_serial, sort_keys=True)
        logger.debug("json_serialization_successful",
                    result_length=len(result))
        return result
        
    except Exception as e:
        logger.error("json_serialization_failed",
                    error=str(e),
                    object_type=type(obj).__name__)
        raise

def redact_sensitive_data(data: Dict[str, Any], sensitive_keys: List[str]) -> Dict[str, Any]:
    """Redact sensitive information from a dictionary."""
    try:
        redacted = data.copy()
        redacted_count = 0
        
        for key in sensitive_keys:
            if key in redacted:
                redacted[key] = "**REDACTED**"
                redacted_count += 1
                
        logger.info("data_redacted",
                   total_fields=len(data),
                   redacted_fields=redacted_count)
        return redacted
        
    except Exception as e:
        logger.error("data_redaction_failed",
                    error=str(e))
        raise