from typing import List, Dict, Any
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from ..core.models import DriftResult
from ..core.logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

class SlackNotifier:
    """Slack notification plugin for drift detection results."""
    
    def __init__(self, token: str, default_channel: str):
        """Initialize Slack notifier with API token and default channel."""
        self.client = WebClient(token=token)
        self.default_channel = default_channel
        logger.info("slack_notifier_initialized",
                   default_channel=default_channel)
        
    async def notify_drift(
        self,
        drift_results: List[DriftResult],
        channel: str | None = None,
        mention_users: List[str] | None = None
    ) -> bool:
        """
        Send drift detection results to Slack.
        
        Args:
            drift_results: List of drift detection results
            channel: Optional override for default channel
            mention_users: Optional list of user IDs to mention
            
        Returns:
            bool: True if notification was successful
        """
        target_channel = channel or self.default_channel
        
        with LogContext(channel=target_channel):
            try:
                with log_duration(logger, "send_slack_notification"):
                    # Prepare message blocks
                    blocks = self._format_drift_message(
                        drift_results,
                        mention_users
                    )
                    
                    logger.debug("sending_slack_message",
                               blocks_count=len(blocks))
                    
                    # Send message
                    response = self.client.chat_postMessage(
                        channel=target_channel,
                        blocks=blocks,
                        text="Infrastructure Drift Detection Results"  # Fallback text
                    )
                    
                    if response["ok"]:
                        logger.info("slack_notification_sent",
                                  message_ts=response["ts"],
                                  thread_ts=response.get("thread_ts"))
                        return True
                    else:
                        logger.error("slack_notification_failed",
                                   error=response.get("error"))
                        return False
                        
            except SlackApiError as e:
                logger.error("slack_api_error",
                           error=str(e),
                           response=e.response)
                return False
            except Exception as e:
                logger.error("notification_error",
                           error=str(e))
                return False
                
    def _format_drift_message(
        self,
        drift_results: List[DriftResult],
        mention_users: List[str] | None = None
    ) -> List[Dict[str, Any]]:
        """Format drift results into Slack message blocks."""
        blocks = []
        
        try:
            # Add header
            header_text = "*Infrastructure Drift Detection Results*"
            if mention_users:
                mentions = ", ".join(f"<@{user}>" for user in mention_users)
                header_text = f"{header_text}\n{mentions}"
            
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": header_text}
            })
            
            # Add summary
            summary = self._create_summary(drift_results)
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": summary}
            })
            
            # Add divider
            blocks.append({"type": "divider"})
            
            # Add detailed results
            for result in drift_results:
                with LogContext(
                    resource_id=result.resource.resource_id,
                    resource_type=result.resource.resource_type,
                    drift_type=result.drift_type.value
                ):
                    try:
                        blocks.extend(self._format_drift_result(result))
                    except Exception as e:
                        logger.error("drift_result_formatting_failed",
                                   error=str(e))
            
            logger.debug("message_blocks_created",
                       block_count=len(blocks))
            return blocks
            
        except Exception as e:
            logger.error("message_formatting_failed",
                        error=str(e))
            # Return basic error message block
            return [{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Error formatting drift results. Please check logs."
                }
            }]
    
    def _create_summary(self, drift_results: List[DriftResult]) -> str:
        """Create a summary of drift detection results."""
        try:
            total = len(drift_results)
            missing = sum(1 for r in drift_results if r.drift_type == "MISSING")
            changed = sum(1 for r in drift_results if r.drift_type == "CHANGED")
            extra = sum(1 for r in drift_results if r.drift_type == "EXTRA")
            
            return (
                f"*Summary:*\n"
                f"• Total issues found: {total}\n"
                f"• Missing resources: {missing}\n"
                f"• Changed resources: {changed}\n"
                f"• Extra resources: {extra}"
            )
            
        except Exception as e:
            logger.error("summary_creation_failed",
                        error=str(e))
            return "*Summary generation failed*"
    
    def _format_drift_result(self, result: DriftResult) -> List[Dict[str, Any]]:
        """Format a single drift result into Slack message blocks."""
        blocks = []
        
        try:
            # Add resource header
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Resource:* `{result.resource.resource_type}`\n"
                        f"*ID:* `{result.resource.resource_id}`\n"
                        f"*Drift Type:* {result.drift_type.value}"
                    )
                }
            })
            
            # Add changes if present
            if result.changes:
                change_text = self._format_changes(result.changes)
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": change_text}
                })
            
            # Add divider between results
            blocks.append({"type": "divider"})
            
            return blocks
            
        except Exception as e:
            logger.error("drift_result_block_creation_failed",
                        error=str(e))
            return [{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Error formatting drift result for {result.resource.resource_id}"
                }
            }]
    
    def _format_changes(self, changes: Dict[str, Any]) -> str:
        """Format resource changes into a readable string."""
        try:
            formatted = ["*Changes:*"]
            
            for key, change in changes.items():
                if change["action"] == "added":
                    formatted.append(f"• Added: `{key}` = `{change['value']}`")
                elif change["action"] == "removed":
                    formatted.append(f"• Removed: `{key}`")
                elif change["action"] == "modified":
                    formatted.append(
                        f"• Modified: `{key}`\n"
                        f"  - From: `{change['old']}`\n"
                        f"  - To: `{change['new']}`"
                    )
            
            return "\n".join(formatted)
            
        except Exception as e:
            logger.error("change_formatting_failed",
                        error=str(e))
            return "*Error formatting changes*"