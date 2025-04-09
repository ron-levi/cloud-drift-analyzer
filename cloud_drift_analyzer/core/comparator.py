from typing import Dict, Any, Tuple, Set
from deepdiff import DeepDiff
from .models import ResourceState
from .logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

class ResourceComparator:
    """Handles detailed comparison of cloud resources."""
    
    @staticmethod
    def compare_resources(
        expected: ResourceState,
        actual: ResourceState
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Compare expected and actual resource states.
        Returns a tuple of (has_differences, changes_dict).
        """
        with LogContext(
            resource_id=expected.resource_id,
            resource_type=expected.resource_type
        ):
            logger.debug("comparing_resources")
            
            # Ignore metadata in comparison
            expected_props = expected.properties
            actual_props = actual.properties
            
            # Use DeepDiff for nested dictionary comparison
            diff = DeepDiff(expected_props, actual_props, ignore_order=True)
            
            if not diff:
                logger.debug("resources_match")
                return False, {}
            
            changes = ResourceComparator._format_changes(diff)
            logger.info("resources_differ",
                       changes_count=len(changes),
                       critical_changes=ResourceComparator._get_critical_changes(
                           expected.resource_type,
                           changes
                       ))
            
            return True, changes
    
    @staticmethod
    def _format_changes(diff: DeepDiff) -> Dict[str, Any]:
        """Convert DeepDiff output to a more user-friendly format."""
        try:
            changes = {}
            
            # Handle value changes
            if "values_changed" in diff:
                for path, change in diff["values_changed"].items():
                    clean_path = path.replace("root['", "").replace("']", "")
                    changes[clean_path] = {
                        "action": "modified",
                        "old": change["old_value"],
                        "new": change["new_value"]
                    }
            
            # Handle dictionary item additions
            if "dictionary_item_added" in diff:
                for path in diff["dictionary_item_added"]:
                    clean_path = path.replace("root['", "").replace("']", "")
                    value = diff.to_dict()["dictionary_item_added"][path]
                    changes[clean_path] = {
                        "action": "added",
                        "value": value
                    }
            
            # Handle dictionary item removals
            if "dictionary_item_removed" in diff:
                for path in diff["dictionary_item_removed"]:
                    clean_path = path.replace("root['", "").replace("']", "")
                    value = diff.to_dict()["dictionary_item_removed"][path]
                    changes[clean_path] = {
                        "action": "removed",
                        "value": value
                    }
                    
            logger.debug("changes_formatted",
                        modified=len(diff.get("values_changed", {})),
                        added=len(diff.get("dictionary_item_added", [])),
                        removed=len(diff.get("dictionary_item_removed", [])))
            
            return changes
            
        except Exception as e:
            logger.error("change_formatting_failed", error=str(e))
            raise
    
    @staticmethod
    def get_critical_properties(resource_type: str) -> Set[str]:
        """
        Get the set of properties that are considered critical for a given resource type.
        Changes to these properties should be highlighted in reports.
        """
        CRITICAL_PROPERTIES = {
            "aws_security_group": {"ingress", "egress"},
            "aws_iam_role": {"assume_role_policy", "policies"},
            "aws_s3_bucket": {"versioning", "encryption"},
            "aws_rds_instance": {"backup_retention_period", "multi_az"},
            # Add more resource types and their critical properties
        }
        
        properties = CRITICAL_PROPERTIES.get(resource_type, set())
        logger.debug("critical_properties_retrieved",
                    resource_type=resource_type,
                    property_count=len(properties))
        return properties
        
    @staticmethod
    def _get_critical_changes(
        resource_type: str,
        changes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract changes to critical properties."""
        critical_props = ResourceComparator.get_critical_properties(resource_type)
        critical_changes = {}
        
        for prop, change in changes.items():
            if prop in critical_props:
                critical_changes[prop] = change
                logger.warning("critical_property_changed",
                             resource_type=resource_type,
                             property=prop,
                             change=change)