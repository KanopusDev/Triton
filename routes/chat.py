import os
import uuid
import json
import logging
import time
import traceback
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, Tuple
from flask import Blueprint, request, jsonify, g, current_app
from azure.ai.inference.models import (
    SystemMessage, UserMessage, AssistantMessage, ToolMessage,
    ChatCompletionsToolCall, CompletionsFinishReason
)
import tiktoken

# Import services
from services.database import DatabaseService
from services.manager import RequestManager
from services.namer import ConversationNamer
from services.monitor import MonitoringService
from services.prompts import SystemPrompts

# Import tools
from tools.search import SearchTools, call_search_function
from tools.research import WebTools, extract_web_content
from tools.reasoning import ReasoningGenerator

# Import image service
from routes.images import get_image_service

# Configure logging
logger = logging.getLogger("triton.chat")

# Create Blueprint
chat_bp = Blueprint('chat', __name__, url_prefix='/api')

# Feature flags
class FeatureFlags:
    """Feature flags to control chat behavior"""
    SEARCH = "search"
    REASONING = "reasoning"
    DEEP_RESEARCH = "deep_research"
    IMAGE_GENERATION = "image_generation"

# Client cache to avoid recreating clients frequently
AI_CLIENT_CACHE = {}

# Get database service instance
def get_db():
    """Get database service instance"""
    if not hasattr(g, 'db_service'):
        db_path = current_app.config.get("DATABASE_PATH", "triton.db")
        g.db_service = DatabaseService(db_path, current_app.config)
    return g.db_service


# Get monitoring service instance
def get_monitor():
    """Get monitoring service instance"""
    if not hasattr(g, 'monitor_service'):
        g.monitor_service = MonitoringService(
            app_name="Triton Chat",
            config=current_app.config
        )
    return g.monitor_service


# Get request manager instance
def get_request_manager(model_id):
    """Get or create a request manager for a specific model"""
    if not hasattr(g, 'request_managers'):
        g.request_managers = {}
    
    if model_id not in g.request_managers:
        ai_client, model_info = get_ai_client(model_id)
        manager = RequestManager(ai_client, model_info)
        g.request_managers[model_id] = manager
    
    return g.request_managers[model_id]


# Get conversation namer instance
def get_namer():
    """Get conversation namer service instance"""
    if not hasattr(g, 'namer_service'):
        g.namer_service = ConversationNamer(
            api_key=current_app.config.get("AZURE_API_KEY")
        )
    return g.namer_service


# Get AI client
def get_ai_client(model_id):
    """Get appropriate AI client and model info based on model_id"""
    from azure.ai.inference import ChatCompletionsClient
    from azure.core.credentials import AzureKeyCredential
    
    # Azure Endpoints
    AZURE_ENDPOINT = "https://models.inference.ai.azure.com"
    
    # Cache key for AI client reuse
    cache_key = f"{model_id}"
    if cache_key in AI_CLIENT_CACHE:
        return AI_CLIENT_CACHE[cache_key]
    
    # Get model info from the options dictionary
    model_info = current_app.config.get("MODEL_OPTIONS", {}).get(model_id)
    
    # If model not in our dictionary, use default settings
    if not model_info:
        logger.warning(f"Model {model_id} not found in MODEL_OPTIONS, using default settings")
        model_info = {
            "id": model_id,
            "name": model_id.split('/')[-1] if '/' in model_id else model_id,
            "tokens": {
                "input": 16384,
                "output": 4096
            }
        }
    
    # Default credentials
    azure_api_key = os.getenv("AZURE_API_KEY")
    
    # Create the client
    logger.info(f"Creating AI client for model: {model_id}")
    client = ChatCompletionsClient(
        endpoint=AZURE_ENDPOINT,
        credential=AzureKeyCredential(azure_api_key)
    )
    
    # Cache the client for reuse
    AI_CLIENT_CACHE[cache_key] = (client, model_info)
    
    return client, model_info


# Main chat endpoint
@chat_bp.route('/chat', methods=['POST'])
def chat():
    """Process a chat request and return AI response
    
    Request body:
    {
        "message": "User message text",
        "conversation_id": "Optional existing conversation ID",
        "model": "Model ID to use (e.g., openai/gpt-4o)",
        "features": {
            "search": true|false,
            "reasoning": true|false,
            "deep_research": true|false,
            "image_generation": true|false
        },
        "generate_image": false  # Optional flag to explicitly generate an image
    }
    
    Returns:
        JSON response with AI message and metadata
    """
    start_time = time.time()
    monitor = get_monitor()
    conversation_id = request.json.get('conversation_id')
    
    try:
        if not g.user:
            return jsonify({"error": "Authentication required"}), 401
        
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        message = data.get('message', '').strip()
        if not message:
            return jsonify({"error": "Message cannot be empty"}), 400
        
        model_id = data.get('model', 'openai/gpt-4o')
        
        # Get feature flags
        features = data.get('features', {})
        
        # Check if explicit image generation is requested
        generate_image = data.get('generate_image', False)
        
        # Create active feature flags dictionary
        active_features = {
            FeatureFlags.SEARCH: bool(features.get('search', False)),
            FeatureFlags.REASONING: bool(features.get('reasoning', False)),
            FeatureFlags.DEEP_RESEARCH: bool(features.get('deep_research', False)),
            FeatureFlags.IMAGE_GENERATION: bool(features.get('image_generation', False))
        }

        # If image generation is explicitly requested, set the feature flag
        if generate_image:
            active_features[FeatureFlags.IMAGE_GENERATION] = True

        # Log enabled features
        logger.info(f"Processing chat request for model: {model_id} with features: {active_features}")
        
        # Check if this is an image generation request
        if active_features[FeatureFlags.IMAGE_GENERATION] and (
            message.lower().startswith("generate image") or 
            message.lower().startswith("create image") or
            message.lower().startswith("draw") or
            "create a picture" in message.lower() or
            generate_image
        ):
            # Handle image generation separately
            return handle_image_generation(message, conversation_id, model_id, data)
        
        # If continuing a conversation, verify ownership
        if conversation_id:
            # Admins can access any conversation, others only their own
            if g.user["role"] != "admin":
                conversation = get_db().execute_query(
                    "SELECT conversation_id FROM conversations WHERE conversation_id = ? AND user_id = ?",
                    (conversation_id, g.user["user_id"]),
                    fetch_mode="one"
                )
                
                if not conversation:
                    return jsonify({"error": "Conversation not found or access denied"}), 403

        # Build system prompt based on enabled features
        prompt_features = {
            "search": active_features[FeatureFlags.SEARCH],
            "reasoning": active_features[FeatureFlags.REASONING],
            "deep_research": active_features[FeatureFlags.DEEP_RESEARCH]
        }
        system_message_content = SystemPrompts.build_system_prompt(prompt_features)

        # Get conversation history
        messages = [SystemMessage(content=system_message_content)]
        
        if conversation_id:
            conversation_messages = get_db().get_conversation_messages(conversation_id)
            
            for message_data in conversation_messages:
                # Validate user message content before adding
                user_msg = message_data.get('user_message')
                if user_msg is not None and isinstance(user_msg, str):
                    messages.append(UserMessage(content=user_msg))
                
                # Validate assistant message content before adding
                assistant_msg = message_data.get('assistant_message')
                if assistant_msg is not None and isinstance(assistant_msg, str):
                    messages.append(AssistantMessage(content=assistant_msg))
        
        # Add current user message
        if message is None or not isinstance(message, str):
            return jsonify({"error": "Invalid message format"}), 400
        
        messages.append(UserMessage(content=message))
        
        # Get AI client and request manager
        request_manager = get_request_manager(model_id)
        
        # Initialize tracking variables
        reasoning = ""
        search_results = []
        
        # Initialize tools based on active features
        tools = []
        
        if active_features[FeatureFlags.SEARCH] or active_features[FeatureFlags.DEEP_RESEARCH]:
            search_tool = SearchTools.get_search_tool_definition()
            tools.append(search_tool)
            
        # Add web extraction tool for deep research
        if active_features[FeatureFlags.DEEP_RESEARCH]:
            web_extraction_tool = WebTools.get_web_extraction_tool_definition()
            tools.append(web_extraction_tool)

        # Process request through request manager
        response = request_manager.process_request(
            messages=messages,
            tools=tools if tools else None,
            model_id=model_id,
            temperature=0.7,
            max_tokens=None,
            tool_choice="auto" if active_features[FeatureFlags.DEEP_RESEARCH] else None
        )
        
        # Extract search results if available in response
        if "tool_results" in response:
            for tool_result in response.get("tool_results", []):
                if tool_result.get("role") == "tool" and tool_result.get("content"):
                    try:
                        # Try to parse search results from tool responses
                        content = tool_result.get("content")
                        if isinstance(content, str):
                            results = json.loads(content)
                            if isinstance(results, list) and results and "title" in results[0]:
                                search_results.extend(results)
                    except Exception as e:
                        logger.warning(f"Error parsing tool result: {str(e)}")
        
        # Generate reasoning if enabled
        if active_features[FeatureFlags.REASONING]:
            ai_client, model_info = get_ai_client(model_id)
            reasoning_generator = ReasoningGenerator(ai_client, model_info)
            reasoning = reasoning_generator.generate_reasoning(message, response.get("content", ""))
        
        # Create or update conversation
        if not conversation_id:
            # Creating a new conversation
            conversation_id = str(uuid.uuid4())
            
            # Generate a descriptive name for the conversation
            namer = get_namer()
            conversation_name = namer.generate_name([{
                "user_message": message,
                "assistant_message": response.get("content", "")
            }])
            
            # Create conversation in database
            get_db().create_conversation({
                "conversation_id": conversation_id,
                "user_id": g.user["user_id"],
                "conversation_name": conversation_name,
                "first_message": message[:100],
            })
        else:
            # Update existing conversation's last activity
            get_db().update_conversation(conversation_id, {
                "updated_at": datetime.now().isoformat()
            })
        
        # Save message to database
        message_id = str(uuid.uuid4())
        get_db().add_message({
            "message_id": message_id,
            "conversation_id": conversation_id,
            "user_message": message,
            "assistant_message": response.get("content", ""),
            "reasoning": reasoning,
            "search_context": search_results,
            "model": model_id,
            "features": features
        })
        
        # Log performance metrics
        response_time = time.time() - start_time
        monitor.log_request(
            path="/api/chat",
            method="POST",
            status_code=200,
            response_time=response_time,
            user_id=g.user["user_id"]
        )
        
        # Return the response
        return jsonify({
            "conversation_id": conversation_id,
            "message": response.get("content", ""),
            "reasoning": reasoning,
            "search_results": search_results if search_results else []
        })
    
    except Exception as e:
        # Log the error with full context
        error_id = monitor.log_error(
            error=e,
            request_info={
                "path": "/api/chat",
                "method": "POST",
                "data": request.json
            },
            user_info=g.user if hasattr(g, 'user') else None
        )
        
        logger.error(f"Chat error ID {error_id}: {str(e)}\n{traceback.format_exc()}")
        
        return jsonify({
            "error": "An error occurred while processing your request",
            "error_id": error_id,
            "conversation_id": conversation_id
        }), 500


# Helper function for image generation
def handle_image_generation(message, conversation_id, model_id, data):
    """Handle image generation request as part of chat flow
    
    Args:
        message: User message
        conversation_id: Conversation ID
        model_id: Model ID
        data: Original request data
        
    Returns:
        JSON response with generated image and metadata
    """
    try:
        # Get image service
        image_service = get_image_service()
        
        if not image_service or not image_service.client:
            # Create a text response for unavailable service
            return jsonify({
                "conversation_id": conversation_id,
                "message": "I'm sorry, image generation is not available right now. The service may be misconfigured or temporarily down.",
                "reasoning": "Image generation requires Google Gemini API to be properly configured.",
                "search_results": []
            })
        
        # Generate image
        result = image_service.generate_image_from_text(
            prompt=message,
            conversation_id=conversation_id,
            user_id=g.user["user_id"]
        )
        
        # Check for errors
        if "error" in result:
            return jsonify({
                "conversation_id": conversation_id,
                "message": f"I'm sorry, I couldn't generate that image. {result['error']}",
                "reasoning": "Image generation failed with an error.",
                "search_results": []
            })
        
        # Save image record
        record_result = image_service.save_image_record(
            user_id=g.user["user_id"],
            prompt=message,
            image_data=result["image_data"],
            conversation_id=conversation_id
        )
        
        # Get database service for conversation handling
        db = get_db()
        
        # Create text response
        text_response = result.get("text_response") or "Here's the image I've created based on your request."
        
        # Create or update conversation if needed
        if not conversation_id:
            # Creating a new conversation
            conversation_id = str(uuid.uuid4())
            
            # Generate a descriptive name for the conversation
            namer = get_namer()
            conversation_name = namer.generate_name([{
                "user_message": message,
                "assistant_message": text_response
            }])
            
            # Create conversation in database
            db.create_conversation({
                "conversation_id": conversation_id,
                "user_id": g.user["user_id"],
                "conversation_name": conversation_name,
                "first_message": message[:100],
            })
        else:
            # Update existing conversation's last activity
            db.update_conversation(conversation_id, {
                "updated_at": datetime.now().isoformat()
            })
        
        # Add message to conversation
        message_id = str(uuid.uuid4())
        db.add_message({
            "message_id": message_id,
            "conversation_id": conversation_id,
            "user_message": message,
            "assistant_message": text_response,
            "reasoning": "",
            "search_context": "[]",
            "model": "gemini-image-generation",
            "features": json.dumps({"image_generation": True})
        })
        
        # Return the response with image data
        return jsonify({
            "conversation_id": conversation_id,
            "message": text_response,
            "image_data": f"data:image/png;base64,{result['image_data']}",
            "image_id": record_result.get("image_id"),
            "reasoning": "",
            "search_results": []
        })
    
    except Exception as e:
        logger.error(f"Image generation error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            "conversation_id": conversation_id,
            "message": "I'm sorry, I encountered an error trying to generate that image. Please try again later.",
            "reasoning": "",
            "search_results": []
        })


# Get conversation messages
@chat_bp.route('/conversations/<conversation_id>', methods=['GET'])
def get_conversation(conversation_id):
    """Get a specific conversation and its messages"""
    try:
        if not g.user:
            return jsonify({"error": "Authentication required"}), 401
            
        db = get_db()
        
        # Check access permission
        if g.user["role"] != "admin":
            # Regular users can only access their own conversations
            conversation = db.execute_query(
                "SELECT * FROM conversations WHERE conversation_id = ? AND user_id = ?",
                (conversation_id, g.user["user_id"]),
                fetch_mode="one"
            )
            
            if not conversation:
                return jsonify({"error": "Conversation not found or access denied"}), 404
        else:
            # Admins can access any conversation
            conversation = db.execute_query(
                "SELECT * FROM conversations WHERE conversation_id = ?",
                (conversation_id,),
                fetch_mode="one"
            )
            
            if not conversation:
                return jsonify({"error": "Conversation not found"}), 404
        
        # Get messages with pagination support
        limit = request.args.get('limit', type=int)
        offset = request.args.get('offset', type=int) 
        
        messages = db.get_conversation_messages(conversation_id, limit, offset)
        
        # Format conversation data
        conversation_data = {
            "conversation_id": conversation["conversation_id"],
            "conversation_name": conversation["conversation_name"],
            "created_at": conversation["created_at"],
            "updated_at": conversation["updated_at"],
            "message_count": conversation["message_count"],
            "messages": messages
        }
        
        return jsonify(conversation_data)
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Get conversation error ID {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e), "error_id": error_id}), 500


# Get user conversations
@chat_bp.route('/conversations', methods=['GET'])
def get_conversations():
    """Get all conversations for the current user with pagination"""
    try:
        if not g.user:
            return jsonify({"error": "Authentication required"}), 401
            
        db = get_db()
        
        # Support pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Calculate offset
        offset = (page - 1) * per_page
        
        # Admin can see all conversations, regular users only their own
        if g.user["role"] == "admin" and request.args.get('all') == 'true':
            # Get conversations for all users
            conversations = db.execute_query(
                """SELECT c.*, u.username as owner_name
                FROM conversations c
                LEFT JOIN users u ON c.user_id = u.user_id
                ORDER BY c.updated_at DESC
                LIMIT ? OFFSET ?""",
                (per_page, offset),
                fetch_mode="all"
            )
            
            # Get total count
            total_count = db.execute_query(
                "SELECT COUNT(*) as count FROM conversations",
                fetch_mode="one"
            )["count"]
            
            # Format results to include owner information
            result = []
            for conversation in conversations:
                result.append({
                    "conversation_id": conversation["conversation_id"],
                    "conversation_name": conversation["conversation_name"],
                    "created_at": conversation["created_at"],
                    "updated_at": conversation["updated_at"],
                    "message_count": conversation["message_count"],
                    "first_message": conversation["first_message"],
                    "last_message": conversation["last_message"],
                    "owner": {
                        "user_id": conversation["user_id"],
                        "username": conversation.get("owner_name")
                    }
                })
        else:
            # Get only the user's conversations
            conversations = db.get_user_conversations(
                g.user["user_id"],
                limit=per_page,
                offset=offset
            )
            
            # Get total count
            total_count = db.execute_query(
                "SELECT COUNT(*) as count FROM conversations WHERE user_id = ?",
                (g.user["user_id"],),
                fetch_mode="one"
            )["count"]
            
            # Use the result directly
            result = conversations
        
        return jsonify({
            "conversations": result,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_count,
                "pages": (total_count + per_page - 1) // per_page
            }
        })
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Get conversations error ID {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e), "error_id": error_id}), 500


# Update conversation
@chat_bp.route('/conversations/<conversation_id>', methods=['PATCH'])
def update_conversation(conversation_id):
    """Update conversation properties"""
    try:
        if not g.user:
            return jsonify({"error": "Authentication required"}), 401
            
        db = get_db()
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Check access permission
        if g.user["role"] != "admin":
            conversation = db.execute_query(
                "SELECT * FROM conversations WHERE conversation_id = ? AND user_id = ?",
                (conversation_id, g.user["user_id"]),
                fetch_mode="one"
            )
            
            if not conversation:
                return jsonify({"error": "Conversation not found or access denied"}), 404
        else:
            conversation = db.execute_query(
                "SELECT * FROM conversations WHERE conversation_id = ?",
                (conversation_id,),
                fetch_mode="one"
            )
            
            if not conversation:
                return jsonify({"error": "Conversation not found"}), 404
        
        # Prepare updates
        updates = {}
        
        # Handle name update
        if 'name' in data:
            updates['conversation_name'] = data['name']
        
        # Handle any other updatable fields
        if not updates:
            return jsonify({"message": "No valid updates provided"}), 400
        
        # Update conversation
        success = db.update_conversation(conversation_id, updates)
        
        if success:
            return jsonify({
                "message": "Conversation updated successfully",
                "conversation_id": conversation_id,
                "updates": updates
            })
        else:
            return jsonify({"error": "Failed to update conversation"}), 500
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Update conversation error ID {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e), "error_id": error_id}), 500


# Delete conversation
@chat_bp.route('/conversations/<conversation_id>', methods=['DELETE'])
def delete_conversation(conversation_id):
    """Delete a conversation"""
    try:
        if not g.user:
            return jsonify({"error": "Authentication required"}), 401
            
        db = get_db()
        
        # Check access permission
        if g.user["role"] != "admin":
            conversation = db.execute_query(
                "SELECT * FROM conversations WHERE conversation_id = ? AND user_id = ?",
                (conversation_id, g.user["user_id"]),
                fetch_mode="one"
            )
            
            if not conversation:
                return jsonify({"error": "Conversation not found or access denied"}), 404
        else:
            conversation = db.execute_query(
                "SELECT * FROM conversations WHERE conversation_id = ?",
                (conversation_id,),
                fetch_mode="one"
            )
            
            if not conversation:
                return jsonify({"error": "Conversation not found"}), 404
        
        # Delete conversation and associated messages
        db.execute_transaction([
            {
                "query": "DELETE FROM messages WHERE conversation_id = ?",
                "params": (conversation_id,)
            },
            {
                "query": "DELETE FROM conversations WHERE conversation_id = ?",
                "params": (conversation_id,)
            }
        ])
        
        return jsonify({
            "message": "Conversation deleted successfully",
            "conversation_id": conversation_id
        })
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Delete conversation error ID {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e), "error_id": error_id}), 500


# Get available models
@chat_bp.route('/models', methods=['GET'])
def get_models():
    """Return available AI models"""
    try:
        if not g.user:
            return jsonify({"error": "Authentication required"}), 401
            
        model_options = current_app.config.get("MODEL_OPTIONS", {})
        return jsonify({"models": model_options})
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Get models error ID {error_id}: {str(e)}")
        return jsonify({"error": str(e), "error_id": error_id}), 500


# Register user authentication middleware
@chat_bp.before_request
def load_user():
    """Load user before processing request"""
    from flask import session, request
    
    # Clear any previous user
    g.user = None
    
    # Check session for authentication
    session_token = session.get('auth_token')
    if session_token:
        db = get_db()
        user_id = db.validate_session(session_token)
        if user_id:
            g.user = db.get_user_by_id(user_id)
            return
    
    # Check Authorization header for JWT tokens (API usage)
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        from jwt import decode, ExpiredSignatureError, InvalidTokenError
        
        try:
            payload = decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = payload.get('user_id')
            if user_id:
                db = get_db()
                g.user = db.get_user_by_id(user_id)
                return
        except (ExpiredSignatureError, InvalidTokenError):
            pass


# Register the blueprint with the Flask app
def register_blueprint(app):
    """Register the chat blueprint with the Flask app"""
    app.register_blueprint(chat_bp)
    logger.info("Chat routes registered")
