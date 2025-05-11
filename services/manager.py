import logging
import json
import re
import time
import uuid
from typing import Dict, List, Any, Optional, Union, Tuple, Callable
from azure.ai.inference.models import (
    SystemMessage, UserMessage, AssistantMessage, ToolMessage,
    ChatCompletionsToolCall, CompletionsFinishReason
)
import tiktoken
import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import traceback
import html

# Configure logging
logger = logging.getLogger("triton.manager")

class RequestManager:
    """
    Manages complex request scenarios including token limit handling, 
    request chunking, and multi-part orchestration
    """
    
    # Default token limits if model-specific ones aren't available
    DEFAULT_TOKEN_LIMITS = {
        "input": 16384,   # 16k context
        "output": 4096    # 4k generation
    }
    
    # Reserved tokens for various operations
    TOKENS_RESERVED_FOR_TOOLS = 1000    # Reserve tokens for potential tool calls
    TOKENS_RESERVED_FOR_RESPONSE = 1000  # Reserve tokens for the response
    TOKENS_OVERLAP = 1000               # Overlap tokens when chunking
    
    # Safety factor to avoid hitting exact token limits (95%)
    SAFETY_FACTOR = 0.95
    
    def __init__(self, ai_client=None, model_info=None):
        """
        Initialize the request manager
        
        Args:
            ai_client: The AI client to use for requests
            model_info: Information about the model including token limits
        """
        self.ai_client = ai_client
        self.model_info = model_info or {}
        self._encoders = {}  # Cache for tokenizers
        self._request_cache = {}  # Cache for multi-part requests
    
    def set_ai_client(self, ai_client, model_info):
        """
        Set or update the AI client and model info
        
        Args:
            ai_client: The AI client to use
            model_info: Information about the model
        """
        self.ai_client = ai_client
        self.model_info = model_info
    
    @lru_cache(maxsize=10)
    def _get_encoder(self, model_name: str):
        """
        Get the appropriate tokenizer for a model
        
        Args:
            model_name: The model name
            
        Returns:
            Tokenizer for the model
        """
        try:
            # Clean up model name for tiktoken
            if '/' in model_name:
                model_name = model_name.split('/')[-1]
            
            # Try to get the specific encoder for this model
            return tiktoken.encoding_for_model(model_name)
        except KeyError:
            # Fall back to cl100k_base for GPT-4 and newer models
            logger.warning(f"No specific tokenizer found for {model_name}, using cl100k_base")
            return tiktoken.get_encoding("cl100k_base")
    
    def estimate_tokens(self, messages: List[Dict[str, Any]], model_name: str = "gpt-4o") -> int:
        """
        Estimate token count for a list of messages
        
        Args:
            messages: List of message objects
            model_name: Model to use for token estimation
            
        Returns:
            int: Estimated token count
        """
        if not messages:
            return 0
        
        try:
            # Get encoder based on model
            encoder = self._get_encoder(model_name)
            
            tokens = 0
            # Add message tokens
            for message in messages:
                # Count 4 tokens for message type and role metadata
                tokens += 4
                
                # Add content tokens if present
                if "content" in message and message["content"]:
                    content = message["content"]
                    if isinstance(content, str):
                        tokens += len(encoder.encode(content))
                
                # Add tokens for tool calls if present
                if "tool_calls" in message and message["tool_calls"]:
                    tool_calls = message["tool_calls"]
                    for tool_call in tool_calls:
                        if isinstance(tool_call, dict):
                            # Count function name and id (approximately)
                            name = tool_call.get("function", {}).get("name", "")
                            tokens += len(encoder.encode(name))
                            
                            # Count arguments
                            args = tool_call.get("function", {}).get("arguments", "{}")
                            if isinstance(args, str):
                                tokens += len(encoder.encode(args))
                            elif isinstance(args, dict):
                                tokens += len(encoder.encode(json.dumps(args)))
            
            # Add a small buffer for format-specific tokens
            tokens += 3
            
            return tokens
        except Exception as e:
            logger.error(f"Error estimating tokens: {str(e)}")
            # Fall back to a crude estimation method (4 tokens per word)
            total_text = " ".join([
                m.get("content", "") for m in messages 
                if isinstance(m.get("content", ""), str)
            ])
            return len(total_text.split()) * 4
    
    def convert_to_standard_messages(self, messages: List[Any]) -> List[Dict[str, Any]]:
        """
        Convert Azure SDK message objects to standard dictionary format
        
        Args:
            messages: List of Azure SDK message objects
            
        Returns:
            List[Dict]: Standardized message dictionaries
        """
        standard_messages = []
        
        for message in messages:
            if isinstance(message, SystemMessage):
                standard_messages.append({"role": "system", "content": message.content})
            elif isinstance(message, UserMessage):
                standard_messages.append({"role": "user", "content": message.content})
            elif isinstance(message, AssistantMessage):
                if hasattr(message, 'tool_calls') and message.tool_calls:
                    tool_calls_data = []
                    for tc in message.tool_calls:
                        tc_data = {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        }
                        tool_calls_data.append(tc_data)
                    
                    standard_messages.append({
                        "role": "assistant", 
                        "content": message.content if hasattr(message, 'content') else None,
                        "tool_calls": tool_calls_data
                    })
                else:
                    standard_messages.append({"role": "assistant", "content": message.content})
            elif isinstance(message, ToolMessage):
                standard_messages.append({
                    "role": "tool", 
                    "content": message.content,
                    "tool_call_id": message.tool_call_id
                })
            elif isinstance(message, dict):
                # Already in standard format
                standard_messages.append(message)
        
        return standard_messages
    
    def _split_message(self, message: str, max_chunk_tokens: int, model_name: str) -> List[str]:
        """
        Split a long message into smaller chunks
        
        Args:
            message: Message text to split
            max_chunk_tokens: Maximum tokens per chunk
            model_name: Model name for token counting
            
        Returns:
            List[str]: List of message chunks
        """
        encoder = self._get_encoder(model_name)
        
        # If message is already under limit, return as is
        message_tokens = len(encoder.encode(message))
        if message_tokens <= max_chunk_tokens:
            return [message]
        
        # Split by paragraphs first
        paragraphs = re.split(r'\n\s*\n', message)
        
        chunks = []
        current_chunk = []
        current_chunk_tokens = 0
        
        for paragraph in paragraphs:
            paragraph_tokens = len(encoder.encode(paragraph))
            
            if current_chunk_tokens + paragraph_tokens <= max_chunk_tokens:
                # Add to current chunk
                current_chunk.append(paragraph)
                current_chunk_tokens += paragraph_tokens
            elif paragraph_tokens > max_chunk_tokens:
                # Paragraph itself is too long, finish current chunk
                if current_chunk:
                    chunks.append("\n\n".join(current_chunk))
                    current_chunk = []
                    current_chunk_tokens = 0
                
                # Split paragraph into sentences
                sentences = re.split(r'(?<=[.!?])\s+', paragraph)
                sentence_chunk = []
                sentence_chunk_tokens = 0
                
                for sentence in sentences:
                    sentence_tokens = len(encoder.encode(sentence))
                    
                    if sentence_chunk_tokens + sentence_tokens <= max_chunk_tokens:
                        # Add to sentence chunk
                        sentence_chunk.append(sentence)
                        sentence_chunk_tokens += sentence_tokens
                    elif sentence_tokens > max_chunk_tokens:
                        # Sentence itself is too long, finish current sentence chunk
                        if sentence_chunk:
                            chunks.append(" ".join(sentence_chunk))
                            sentence_chunk = []
                            sentence_chunk_tokens = 0
                        
                        # Split into words as a last resort
                        words = sentence.split()
                        word_chunk = []
                        word_chunk_tokens = 0
                        
                        for word in words:
                            word_tokens = len(encoder.encode(word + " "))
                            
                            if word_chunk_tokens + word_tokens <= max_chunk_tokens:
                                word_chunk.append(word)
                                word_chunk_tokens += word_tokens
                            else:
                                # Add word chunk and start a new one
                                if word_chunk:
                                    chunks.append(" ".join(word_chunk))
                                word_chunk = [word]
                                word_chunk_tokens = word_tokens
                        
                        # Add any remaining words
                        if word_chunk:
                            chunks.append(" ".join(word_chunk))
                    else:
                        # Start a new sentence chunk
                        if sentence_chunk:
                            chunks.append(" ".join(sentence_chunk))
                        sentence_chunk = [sentence]
                        sentence_chunk_tokens = sentence_tokens
                
                # Add any remaining sentences
                if sentence_chunk:
                    chunks.append(" ".join(sentence_chunk))
            else:
                # Start a new chunk
                if current_chunk:
                    chunks.append("\n\n".join(current_chunk))
                current_chunk = [paragraph]
                current_chunk_tokens = paragraph_tokens
        
        # Add any remaining paragraphs
        if current_chunk:
            chunks.append("\n\n".join(current_chunk))
        
        return chunks
    
    def chunk_conversation(self, messages: List[Dict[str, Any]], model_name: str) -> List[List[Dict[str, Any]]]:
        """
        Split a conversation into multiple chunks if it exceeds token limits
        
        Args:
            messages: List of message dictionaries
            model_name: Model name for token estimation
            
        Returns:
            List[List[Dict]]: List of message chunks
        """
        # Get token limits for this model
        token_limits = self.model_info.get("tokens", self.DEFAULT_TOKEN_LIMITS)
        max_input_tokens = int(token_limits.get("input", self.DEFAULT_TOKEN_LIMITS["input"]) * self.SAFETY_FACTOR)
        
        # Estimate total tokens
        total_tokens = self.estimate_tokens(messages, model_name)
        
        # If within limits, return as is
        if total_tokens <= max_input_tokens:
            return [messages]
        
        # Need to chunk the conversation
        logger.info(f"Chunking conversation of {total_tokens} tokens (limit: {max_input_tokens})")
        
        # Always keep the system message in all chunks
        system_message = next((m for m in messages if m.get("role") == "system"), None)
        
        # Calculate max tokens per chunk, reserving space for system message
        system_tokens = self.estimate_tokens([system_message], model_name) if system_message else 0
        
        # Reserve tokens for system message, tools, and overlap between chunks
        available_tokens = max_input_tokens - system_tokens - self.TOKENS_RESERVED_FOR_TOOLS
        
        # Safety check
        if available_tokens <= 0:
            logger.error(f"System message too large ({system_tokens} tokens), can't chunk effectively")
            # Return just the system message and last user message as fallback
            last_user_message = next((m for m in reversed(messages) if m.get("role") == "user"), None)
            if last_user_message:
                return [[system_message, last_user_message]] if system_message else [[last_user_message]]
            return [[system_message]] if system_message else [[]]
        
        chunks = []
        current_chunk = [system_message] if system_message else []
        current_chunk_tokens = system_tokens
        
        # Start building chunks, always maintaining chronological order
        # Skip system message as we've already handled it
        for message in [m for m in messages if m.get("role") != "system"]:
            message_tokens = self.estimate_tokens([message], model_name)
            
            # Special handling for really large messages
            if message_tokens > available_tokens:
                # Finish current chunk if not empty
                if len(current_chunk) > (1 if system_message else 0):  # More than just system message
                    chunks.append(current_chunk)
                
                # Split the large message
                if message.get("role") == "user" and isinstance(message.get("content"), str):
                    # We can only split user message content
                    content_chunks = self._split_message(
                        message["content"], 
                        available_tokens - 50,  # Reserve some tokens for message metadata
                        model_name
                    )
                    
                    # Create a new chunk for each content piece
                    for i, content_chunk in enumerate(content_chunks):
                        # Add chunk header for all but first chunk
                        if i > 0:
                            content_chunk = f"[Continued from previous message, part {i+1}/{len(content_chunks)}]\n\n{content_chunk}"
                        
                        chunk_message = {**message, "content": content_chunk}
                        new_chunk = [system_message] if system_message else []
                        new_chunk.append(chunk_message)
                        chunks.append(new_chunk)
                else:
                    # Can't split non-user messages or messages without content, use trimming
                    logger.warning(f"Can't split non-user message of {message_tokens} tokens")
                    if message.get("content") and isinstance(message.get("content"), str):
                        # Trim the content
                        content = message["content"]
                        trimmed_message = {**message}
                        trimmed_message["content"] = content[:int(len(content) * (available_tokens / message_tokens))] + "...[content truncated due to length]"
                        
                        new_chunk = [system_message] if system_message else []
                        new_chunk.append(trimmed_message)
                        chunks.append(new_chunk)
                
                # Reset current chunk
                current_chunk = [system_message] if system_message else []
                current_chunk_tokens = system_tokens
            elif current_chunk_tokens + message_tokens > available_tokens:
                # Current chunk is full, start a new one
                chunks.append(current_chunk)
                current_chunk = [system_message] if system_message else []
                current_chunk.append(message)
                current_chunk_tokens = system_tokens + message_tokens
            else:
                # Add to current chunk
                current_chunk.append(message)
                current_chunk_tokens += message_tokens
        
        # Add the last chunk if not empty
        if len(current_chunk) > (1 if system_message else 0):  # More than just system message
            chunks.append(current_chunk)
        
        logger.info(f"Split conversation into {len(chunks)} chunks")
        return chunks
    
    async def process_request(self, 
                             messages: List[Any], 
                             tools: Optional[List[Any]] = None,
                             model_id: str = "gpt-4o",
                             temperature: float = 0.7,
                             max_tokens: Optional[int] = None,
                             tool_choice: Optional[Any] = None) -> Dict[str, Any]:
        """
        Process a request, handling token limits and chunking if needed
        
        Args:
            messages: List of message objects
            tools: Optional list of tool definitions
            model_id: The model to use
            temperature: Temperature for generation
            max_tokens: Maximum tokens to generate
            tool_choice: Tool choice parameter
            
        Returns:
            Dict: Processed response
        """
        if not self.ai_client:
            raise ValueError("AI client not set. Use set_ai_client() first.")
        
        # Convert messages to standard format for token counting
        std_messages = self.convert_to_standard_messages(messages)
        
        # Get model info
        model_name = model_id.split('/')[-1] if '/' in model_id else model_id
        
        # Get token limits for this model
        token_limits = self.model_info.get("tokens", self.DEFAULT_TOKEN_LIMITS)
        max_input_tokens = token_limits.get("input", self.DEFAULT_TOKEN_LIMITS["input"])
        max_output = max_tokens or token_limits.get("output", self.DEFAULT_TOKEN_LIMITS["output"])
        
        # Estimate tokens
        estimated_tokens = self.estimate_tokens(std_messages, model_name)
        logger.info(f"Request estimated at {estimated_tokens} tokens (limit: {max_input_tokens})")
        
        # Check if we need to chunk the request
        if estimated_tokens > max_input_tokens * self.SAFETY_FACTOR:
            return await self._process_chunked_request(
                std_messages, tools, model_id, temperature, max_output, tool_choice
            )
        
        # Standard request
        try:
            # Use the original message objects for the actual request
            response = self.ai_client.complete(
                messages=messages,
                tools=tools,
                model=model_id,
                temperature=temperature,
                max_tokens=max_output,
                tool_choice=tool_choice
            )
            
            return self._create_response_object(response)
        except Exception as e:
            logger.error(f"Error processing request: {str(e)}\n{traceback.format_exc()}")
            
            # Try fallback to stripped request
            try:
                # Try with simplified messages (just system and last user message)
                system_message = next((m for m in messages if isinstance(m, SystemMessage)), None)
                last_user_message = next((m for m in reversed(messages) if isinstance(m, UserMessage)), None)
                
                if system_message and last_user_message:
                    logger.info("Attempting fallback with simplified messages")
                    simplified_messages = [system_message, last_user_message]
                    
                    response = self.ai_client.complete(
                        messages=simplified_messages,
                        tools=tools,
                        model=model_id,
                        temperature=temperature,
                        max_tokens=max_output,
                        tool_choice=tool_choice
                    )
                    
                    return self._create_response_object(response)
            except Exception as fallback_error:
                logger.error(f"Fallback also failed: {str(fallback_error)}")
            
            # If all attempts fail, return error response
            return {
                "error": True,
                "message": f"Error processing request: {str(e)}",
                "content": "I encountered an error processing your request. Please try again or simplify your message."
            }
    
    async def _process_chunked_request(self,
                                     messages: List[Dict[str, Any]],
                                     tools: Optional[List[Any]] = None,
                                     model_id: str = "gpt-4o",
                                     temperature: float = 0.7,
                                     max_tokens: int = 4096,
                                     tool_choice: Optional[Any] = None) -> Dict[str, Any]:
        """
        Process a request that requires chunking due to token limits
        
        Args:
            messages: List of standardized message dictionaries
            tools: Optional list of tool definitions
            model_id: The model to use
            temperature: Temperature for generation
            max_tokens: Maximum tokens to generate
            tool_choice: Tool choice parameter
            
        Returns:
            Dict: Processed response
        """
        # Generate a request ID for tracking
        request_id = str(uuid.uuid4())
        model_name = model_id.split('/')[-1] if '/' in model_id else model_id
        
        # Split conversation into chunks
        chunks = self.chunk_conversation(messages, model_name)
        
        if not chunks:
            return {
                "error": True,
                "message": "Failed to chunk conversation effectively",
                "content": "Your message is too long for me to process. Please break it into smaller parts."
            }
        
        logger.info(f"Processing request {request_id} in {len(chunks)} chunks")
        
        # Process each chunk and collect intermediate results
        intermediate_results = []
        aggregated_tool_results = []
        
        for i, chunk in enumerate(chunks):
            logger.info(f"Processing chunk {i+1}/{len(chunks)}")
            
            # Convert dictionaries back to SDK message objects
            sdk_messages = self._convert_to_sdk_messages(chunk)
            
            # Process chunk
            try:
                # Use tools only on the last chunk for multi-chunk requests
                chunk_tools = tools if i == len(chunks) - 1 or len(chunks) == 1 else None
                chunk_tool_choice = tool_choice if i == len(chunks) - 1 or len(chunks) == 1 else None
                
                if i < len(chunks) - 1:
                    # For all but the last chunk, add a continuation prompt
                    continuation_msg = f"\n\nNote: This is part {i+1} of a longer conversation. Please provide an initial analysis only."
                    last_user_idx = None
                    
                    for j, msg in enumerate(sdk_messages):
                        if isinstance(msg, UserMessage):
                            last_user_idx = j
                    
                    if last_user_idx is not None:
                        user_msg = sdk_messages[last_user_idx]
                        sdk_messages[last_user_idx] = UserMessage(content=user_msg.content + continuation_msg)
                
                # Make the actual API call
                response = self.ai_client.complete(
                    messages=sdk_messages,
                    tools=chunk_tools,
                    model=model_id,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tool_choice=chunk_tool_choice
                )
                
                # Process tool calls if any
                tool_results = await self._process_tool_calls(response, tools, sdk_messages, model_id, temperature, max_tokens)
                if tool_results:
                    aggregated_tool_results.extend(tool_results)
                
                # Collect result
                if hasattr(response.choices[0].message, 'content') and response.choices[0].message.content:
                    intermediate_results.append(response.choices[0].message.content)
                    
            except Exception as e:
                logger.error(f"Error processing chunk {i+1}: {str(e)}\n{traceback.format_exc()}")
                intermediate_results.append(f"[Error processing this part: {str(e)}]")
        
        # If we have tool results, make a final request combining everything
        final_response = None
        if aggregated_tool_results:
            try:
                # Create a summary request with original system message and tool results
                system_message = next((m for m in messages if m.get("role") == "system"), None)
                last_user_message = next((m for m in reversed(messages) if m.get("role") == "user"), None)
                
                if system_message and last_user_message:
                    # Build final messages array
                    final_messages = []
                    
                    # Convert back to SDK objects
                    if system_message:
                        final_messages.append(SystemMessage(content=system_message.get("content", "")))
                    
                    # Add the last user message
                    if last_user_message:
                        final_messages.append(UserMessage(content=last_user_message.get("content", "")))
                    
                    # Add all tool results
                    for result in aggregated_tool_results:
                        if isinstance(result, dict) and "role" in result:
                            # Convert dict to SDK object
                            if result["role"] == "assistant" and "tool_calls" in result:
                                tool_calls = result["tool_calls"]
                                final_messages.append(AssistantMessage(tool_calls=tool_calls))
                            elif result["role"] == "tool":
                                final_messages.append(ToolMessage(
                                    tool_call_id=result.get("tool_call_id", ""),
                                    content=result.get("content", "")
                                ))
                        else:
                            # Already SDK object
                            final_messages.append(result)
                    
                    # Make final request
                    final_response = self.ai_client.complete(
                        messages=final_messages,
                        tools=None,  # No tools in final summary
                        model=model_id,
                        temperature=temperature,
                        max_tokens=max_tokens
                    )
            except Exception as e:
                logger.error(f"Error creating final response: {str(e)}\n{traceback.format_exc()}")
        
        # If we have a valid final response with tool results, use it
        if final_response and hasattr(final_response.choices[0].message, 'content') and final_response.choices[0].message.content:
            return self._create_response_object(final_response)
        
        # Otherwise aggregate the intermediate results
        aggregated_content = self._aggregate_results(intermediate_results)
        
        # Create a mock response object
        return {
            "content": aggregated_content,
            "role": "assistant",
            "chunked": True,
            "chunks_processed": len(chunks),
            "tool_results": bool(aggregated_tool_results)
        }
    
    async def _process_tool_calls(self, 
                               response, 
                               tools: List[Any],
                               messages: List[Any],
                               model_id: str,
                               temperature: float,
                               max_tokens: int) -> List[Dict[str, Any]]:
        """
        Process tool calls from a response
        
        Args:
            response: AI response object
            tools: List of tool definitions
            messages: Current message history
            model_id: The model ID
            temperature: Temperature for generation
            max_tokens: Maximum tokens to generate
            
        Returns:
            List[Dict]: List of tool messages
        """
        if not tools or not hasattr(response.choices[0], 'finish_reason') or response.choices[0].finish_reason != CompletionsFinishReason.TOOL_CALLS:
            return []
        
        if not hasattr(response.choices[0].message, 'tool_calls') or not response.choices[0].message.tool_calls:
            return []
        
        # Process tool calls
        tool_handlers = {}
        for tool in tools:
            if hasattr(tool, 'function') and hasattr(tool.function, 'name'):
                # Extract function name from tool definition
                tool_name = tool.function.name
                # Import the appropriate handler dynamically
                if tool_name == "search_internet":
                    from tools.search import call_search_function
                    tool_handlers[tool_name] = call_search_function
                elif tool_name == "extract_web_content":
                    from tools.research import extract_web_content
                    tool_handlers[tool_name] = extract_web_content
        
        # Create assistant message with tool calls
        tool_messages = []
        tool_messages.append({
            "role": "assistant",
            "tool_calls": response.choices[0].message.tool_calls
        })
        
        # Process each tool call
        for tool_call in response.choices[0].message.tool_calls:
            function_name = tool_call.function.name
            
            if function_name in tool_handlers:
                try:
                    # Parse function arguments
                    function_args = json.loads(tool_call.function.arguments)
                    
                    # Call the function
                    function_result = tool_handlers[function_name](function_args)
                    
                    # Add tool message
                    tool_messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": function_result
                    })
                    
                except Exception as e:
                    logger.error(f"Error processing tool call: {str(e)}")
                    # Add error message
                    tool_messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps({"error": str(e)})
                    })
        
        return tool_messages
    
    def _convert_to_sdk_messages(self, messages: List[Dict[str, Any]]) -> List[Any]:
        """
        Convert standard message dictionaries to Azure SDK message objects
        
        Args:
            messages: List of message dictionaries
            
        Returns:
            List: List of SDK message objects
        """
        sdk_messages = []
        
        for message in messages:
            role = message.get("role", "")
            
            if role == "system":
                sdk_messages.append(SystemMessage(content=message.get("content", "")))
            elif role == "user":
                sdk_messages.append(UserMessage(content=message.get("content", "")))
            elif role == "assistant":
                if "tool_calls" in message and message["tool_calls"]:
                    # Need to convert tool calls to SDK objects
                    sdk_messages.append(AssistantMessage(
                        content=message.get("content", ""),
                        tool_calls=message["tool_calls"]  # This should be SDK objects but is often passed through
                    ))
                else:
                    sdk_messages.append(AssistantMessage(content=message.get("content", "")))
            elif role == "tool":
                sdk_messages.append(ToolMessage(
                    tool_call_id=message.get("tool_call_id", ""),
                    content=message.get("content", "")
                ))
        
        return sdk_messages
    
    def _aggregate_results(self, results: List[str]) -> str:
        """
        Aggregate multiple response chunks into a coherent response
        
        Args:
            results: List of content chunks from multiple responses
            
        Returns:
            str: Aggregated content
        """
        if not results:
            return "I wasn't able to generate a proper response. Please try again."
        
        if len(results) == 1:
            return results[0]
        
        # Simple approach: concatenate with clear markers
        aggregated = "I've analyzed your request in multiple parts:\n\n"
        
        for i, result in enumerate(results):
            if i > 0:
                aggregated += f"\n\n--- Part {i+1} ---\n\n"
            aggregated += result.strip()
        
        # Add a synthesized conclusion for multi-part responses
        if len(results) > 1:
            aggregated += "\n\n--- Summary ---\n\nI've provided analysis across multiple sections due to the complexity of your request. Please let me know if you'd like me to focus on any specific aspect in more detail."
        
        return aggregated
    
    def _create_response_object(self, response) -> Dict[str, Any]:
        """
        Create a standardized response object from the AI response
        
        Args:
            response: AI response object
            
        Returns:
            Dict: Standardized response dictionary
        """
        if not hasattr(response, 'choices') or not response.choices:
            return {
                "error": True,
                "message": "Invalid response from AI service",
                "content": "I experienced an error generating a response. Please try again."
            }
        
        response_obj = {
            "role": "assistant",
            "content": response.choices[0].message.content if hasattr(response.choices[0].message, 'content') else "",
            "finish_reason": response.choices[0].finish_reason if hasattr(response.choices[0], 'finish_reason') else None,
        }
        
        # Add tool calls if present
        if (hasattr(response.choices[0], 'finish_reason') and 
            response.choices[0].finish_reason == CompletionsFinishReason.TOOL_CALLS and
            hasattr(response.choices[0].message, 'tool_calls')):
            
            response_obj["tool_calls"] = response.choices[0].message.tool_calls
        
        return response_obj
