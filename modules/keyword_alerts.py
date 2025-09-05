"""
Keyword alerts module for Synapse
Notifies admin when specific keywords are mentioned
"""

import logging
from typing import Dict, Any

from synapse.module_api import ModuleApi

logger = logging.getLogger(__name__)


class KeywordAlertsModule:
    def __init__(self, config: Dict[str, Any], api: ModuleApi):
        self.api = api
        self.keywords = config.get("keywords", [])
        self.admin_user = config.get("admin_user", "@admin:localhost")
        
        logger.info(f"KeywordAlertsModule initialized with keywords: {self.keywords}")
        
        # Register the event handler
        self.api.register_third_party_rules_callbacks(
            check_event_allowed=self.check_event_allowed
        )

    async def check_event_allowed(
        self, event, state
    ):
        """
        Check for keywords and send alerts to admin
        """
        try:
            # Only check text events
            if event.type != "m.room.message":
                return True
                
            # Get the message content
            content = event.content
            if not content or "body" not in content:
                return True
                
            message_text = content["body"].lower()
            
            # Check for keywords
            found_keywords = []
            for keyword in self.keywords:
                if keyword.lower() in message_text:
                    found_keywords.append(keyword)
            
            if found_keywords:
                logger.info(
                    f"Keyword alert triggered for {event.sender} in room {event.room_id}: {found_keywords}"
                )
                
                # Send alert to admin
                alert_message = (
                    f"🚨 KEYWORD ALERT 🚨\n"
                    f"Room: {event.room_id}\n"
                    f"User: {event.sender}\n"
                    f"Keywords found: {', '.join(found_keywords)}\n"
                    f"Message: {content['body'][:100]}..."
                )
                
                # Create a direct message room with admin if it doesn't exist
                try:
                    # Send notification to admin
                    await self.api.create_and_send_event_into_room(
                        {
                            "type": "m.room.message",
                            "content": {
                                "msgtype": "m.text",
                                "body": alert_message
                            },
                            "sender": "@alerts:localhost"
                        },
                        event.room_id  # Send to the same room for now
                    )
                except Exception as e:
                    logger.error(f"Failed to send keyword alert: {e}")
                    
            return True  # Always allow the original message
            
        except Exception as e:
            logger.error(f"Error in keyword alerts check: {e}")
            return True  # Allow on error


def create_module(config: Dict[str, Any], api: ModuleApi):
    return KeywordAlertsModule(config, api)
