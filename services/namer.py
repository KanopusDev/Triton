import logging
import os
from typing import List, Dict, Any, Optional, Union
from azure.ai.inference import ChatCompletionsClient
from azure.ai.inference.models import SystemMessage, UserMessage
from azure.core.credentials import AzureKeyCredential
import json
import re

# Configure logging
logger = logging.getLogger("triton.namer")

class ConversationNamer:
    """Service for generating descriptive names for conversations using AI"""
    
    # Model to use for generating names
    MODEL_ID = "openai/gpt-4.1-nano"
    AZURE_ENDPOINT = "https://models.inference.ai.azure.com"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the conversation namer
        
        Args:
            api_key: Azure API key (defaults to environment variable)
        """
        self.api_key = api_key or os.getenv("AZURE_API_KEY")
        if not self.api_key:
            logger.warning("No API key provided for ConversationNamer. Falling back to basic naming.")
        
        self.client = None
        if self.api_key:
            self.client = ChatCompletionsClient(
                endpoint=self.AZURE_ENDPOINT,
                credential=AzureKeyCredential(self.api_key)
            )
    
    def generate_name(self, messages: List[Dict[str, str]], max_length: int = 50) -> str:
        """
        Generate a descriptive name for a conversation based on its messages
        
        Args:
            messages: List of message objects with 'user_message' and 'assistant_message' keys
            max_length: Maximum length of the generated name
            
        Returns:
            str: Generated conversation name
        """
        # If we don't have an API client or there are no messages, use fallback naming
        if not self.client or not messages:
            return self._fallback_name(messages)
            
        try:
            # Extract the first user message as the main topic indicator
            first_message = next((m.get('user_message', '') for m in messages if m.get('user_message')), '')
            if not first_message:
                return self._fallback_name(messages)
                
            # Create a simplified conversation history for context (up to 3 exchanges)
            conversation_context = []
            for i, message in enumerate(messages[:3]):
                if message.get('user_message'):
                    conversation_context.append(f"User: {message['user_message']}")
                if message.get('assistant_message'):
                    # Truncate assistant messages to keep prompt size manageable
                    asst_msg = message['assistant_message']
                    if len(asst_msg) > 150:
                        asst_msg = asst_msg[:150] + "..."
                    conversation_context.append(f"Assistant: {asst_msg}")
            
            context_text = "\n".join(conversation_context)
            
            # Create the naming prompt
            system_message = SystemMessage(content="""You are a conversation naming service. 
Your task is to generate a concise, descriptive name for a conversation based on its content.
The name should be clear, relevant, and under 50 characters.
Only respond with the name itself, nothing else.""")
            
            user_message = UserMessage(content=f"""Based on the following conversation excerpt, 
create a descriptive title that captures the main topic or purpose of the conversation:

{context_text}

Generate ONLY the title, nothing else. Keep it under {max_length} characters.""")
            
            # Call the AI model to generate a name
            response = self.client.complete(
                messages=[system_message, user_message],
                model=self.MODEL_ID,
                temperature=0.7,
                max_tokens=100
            )
            
            generated_name = response.choices[0].message.content.strip()
            
            # Clean up the generated name
            generated_name = re.sub(r'^["\'"]|["\'""]$', '', generated_name)  # Remove quotes
            generated_name = re.sub(r'Title: |Name: ', '', generated_name)    # Remove prefixes
            
            # Ensure the name is within the max length
            if len(generated_name) > max_length:
                generated_name = generated_name[:max_length-3] + "..."
                
            logger.info(f"Generated conversation name: {generated_name}")
            return generated_name
            
        except Exception as e:
            logger.error(f"Error generating conversation name: {str(e)}")
            return self._fallback_name(messages)
    
    def _fallback_name(self, messages: List[Dict[str, str]]) -> str:
        """
        Create a basic name based on the first message when AI naming fails
        
        Args:
            messages: List of message objects with 'user_message' and 'assistant_message' keys
            
        Returns:
            str: Basic conversation name
        """
        # Extract the first user message
        first_message = ""
        if messages:
            first_message = next((m.get('user_message', '') for m in messages if m.get('user_message')), '')
        
        # If no messages or empty first message, use a default name
        if not first_message:
            return "New Conversation"
        
        # Create a simple name from the first 50 characters of the message
        name = first_message[:50]
        if len(first_message) > 50:
            name += "..."
            
        return name
