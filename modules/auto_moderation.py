"""
Auto-moderation module for Synapse
Automatically deletes messages containing banned words
"""

import logging
from typing import Dict, Any

from synapse.module_api import ModuleApi

logger = logging.getLogger(__name__)


class AutoModerationModule:
    def __init__(self, config: Dict[str, Any], api: ModuleApi):
        self.api = api
        self.banned_words = config.get("banned_words", [])
        self.action = config.get("action", "delete")
        
        logger.info(f"AutoModerationModule initialized with banned words: {self.banned_words}")
        
        # Register the event handler
        self.api.register_third_party_rules_callbacks(
            check_event_allowed=self.check_event_allowed
        )

    async def check_event_allowed(
        self, event, state
    ):
        """
        Check if an event should be allowed or blocked
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
            
            # Check for banned words
            for banned_word in self.banned_words:
                if banned_word.lower() in message_text:
                    logger.warning(
                        f"Blocked message from {event.sender} containing banned word: {banned_word}"
                    )
                    
                    # Log the moderation action
                    await self.api.create_and_send_event_into_room(
                        {
                            "type": "m.room.message",
                            "content": {
                                "msgtype": "m.text",
                                "body": f"Message deleted by auto-moderation (contained banned word: {banned_word})"
                            },
                            "sender": "@moderator:localhost"
                        },
                        event.room_id
                    )
                    
                    return False  # Block the event
                    
            return True  # Allow the event
            
        except Exception as e:
            logger.error(f"Error in auto-moderation check: {e}")
            return True  # Allow on error to avoid breaking the server


def create_module(config: Dict[str, Any], api: ModuleApi):
    return AutoModerationModule(config, api)
