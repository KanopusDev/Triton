import os
import uuid
import json
import logging
import time
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from flask import Blueprint, request, jsonify, g, current_app, send_file
from werkzeug.utils import secure_filename
import threading
from io import BytesIO
import base64

# Google Gemini imports
from google import genai
from google.genai import types
from PIL import Image as PILImage

# Import services
from services.database import DatabaseService
from services.monitor import MonitoringService

# Configure logging
logger = logging.getLogger("triton.images")

# Create Blueprint
images_bp = Blueprint('images', __name__, url_prefix='/api/images')

# Global client cache
GEMINI_CLIENT = None
GEMINI_CLIENT_LOCK = threading.Lock()

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
            app_name="Triton Images",
            config=current_app.config
        )
    return g.monitor_service

# Initialize Google Gemini client
def get_gemini_client():
    """Get or initialize Google Gemini client"""
    global GEMINI_CLIENT
    
    if GEMINI_CLIENT is None:
        with GEMINI_CLIENT_LOCK:
            if GEMINI_CLIENT is None:
                # Get API key from environment or config
                api_key = current_app.config.get("GEMINI_API_KEY", os.getenv("GEMINI_API_KEY"))

                if not api_key:
                    logger.warning("No Google API key found - image generation will not work")
                    return None
                
                # Initialize client
                try:
                    genai.configure(api_key=api_key)
                    GEMINI_CLIENT = genai.Client()
                    logger.info("Google Gemini client initialized successfully")
                except Exception as e:
                    logger.error(f"Failed to initialize Google Gemini client: {str(e)}")
                    return None
    
    return GEMINI_CLIENT

class ImageService:
    """Service for handling image generation and editing via Google Gemini API"""
    
    # Models
    TEXT_TO_IMAGE_MODEL = "gemini-2.0-flash-preview-image-generation"
    IMAGE_EDIT_MODEL = "gemini-2.0-flash-preview-image-generation"
    
    # Cache configuration
    CACHE_EXPIRY = 3600  # 1 hour cache for generated images
    MAX_CACHE_SIZE = 100  # Maximum number of cached generations
    
    def __init__(self):
        """Initialize the image service"""
        self.client = get_gemini_client()
        self.cache = {}  # Simple in-memory cache for image results
        self.cache_lock = threading.Lock()
        
        # Track rate limits
        self.rate_limits = {}
        self.rate_limit_lock = threading.Lock()
    
    def check_rate_limit(self, user_id: str, limit: int = 10, window: int = 60) -> bool:
        """
        Check if user has exceeded rate limit
        
        Args:
            user_id: User ID
            limit: Maximum number of requests per window
            window: Time window in seconds
            
        Returns:
            bool: True if within limit, False if exceeded
        """
        current_time = time.time()
        
        with self.rate_limit_lock:
            # Initialize user record if not exists
            if user_id not in self.rate_limits:
                self.rate_limits[user_id] = []
            
            # Remove timestamps outside the current window
            self.rate_limits[user_id] = [t for t in self.rate_limits[user_id] 
                                        if current_time - t < window]
            
            # Check if limit exceeded
            if len(self.rate_limits[user_id]) >= limit:
                return False
            
            # Add current timestamp
            self.rate_limits[user_id].append(current_time)
            return True
    
    def generate_image_from_text(self, prompt: str, 
                               conversation_id: Optional[str] = None,
                               user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate an image from a text prompt
        
        Args:
            prompt: Text prompt describing the image
            conversation_id: Optional conversation ID for context
            user_id: User ID for tracking and rate limiting
            
        Returns:
            Dict with generation results
        """
        if not self.client:
            return {"error": "Image generation service unavailable - API key not configured"}
        
        # Generate cache key
        cache_key = f"text2img_{hash(prompt)}_{user_id}"
        
        # Check cache
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            logger.info(f"Returning cached image for prompt: {prompt[:30]}...")
            return cached_result
        
        # Check rate limit
        if user_id and not self.check_rate_limit(user_id):
            return {"error": "Rate limit exceeded. Please try again later."}
        
        try:
            logger.info(f"Generating image from prompt: {prompt[:50]}...")
            
            # Generate image
            response = self.client.models.generate_content(
                model=self.TEXT_TO_IMAGE_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_modalities=['TEXT', 'IMAGE']
                )
            )
            
            # Process results
            result = self._process_gemini_response(response)
            
            # Cache result if successful
            if "error" not in result:
                self._add_to_cache(cache_key, result)
            
            # Log successful generation
            logger.info(f"Successfully generated image from text prompt")
            
            return result
            
        except Exception as e:
            error_message = str(e)
            logger.error(f"Image generation error: {error_message}\n{traceback.format_exc()}")
            return {"error": f"Failed to generate image: {error_message}"}
    
    def edit_image(self, image_data: bytes, prompt: str, 
                  user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Edit an image based on a text prompt
        
        Args:
            image_data: Original image binary data
            prompt: Text prompt describing the desired edits
            user_id: User ID for tracking and rate limiting
            
        Returns:
            Dict with edited image results
        """
        if not self.client:
            return {"error": "Image editing service unavailable - API key not configured"}
        
        # Check rate limit
        if user_id and not self.check_rate_limit(user_id):
            return {"error": "Rate limit exceeded. Please try again later."}
        
        try:
            logger.info(f"Editing image with prompt: {prompt[:50]}...")
            
            # Load image
            try:
                image = PILImage.open(BytesIO(image_data))
            except Exception as img_error:
                return {"error": f"Invalid image format: {str(img_error)}"}
            
            # Generate image
            response = self.client.models.generate_content(
                model=self.IMAGE_EDIT_MODEL,
                contents=[prompt, image],
                config=types.GenerateContentConfig(
                    response_modalities=['TEXT', 'IMAGE']
                )
            )
            
            # Process results
            result = self._process_gemini_response(response)
            
            # Log successful edit
            logger.info(f"Successfully edited image")
            
            return result
            
        except Exception as e:
            error_message = str(e)
            logger.error(f"Image editing error: {error_message}\n{traceback.format_exc()}")
            return {"error": f"Failed to edit image: {error_message}"}
    
    def _process_gemini_response(self, response) -> Dict[str, Any]:
        """
        Process response from Gemini API
        
        Args:
            response: Gemini API response
            
        Returns:
            Dict with processed results
        """
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "model": self.TEXT_TO_IMAGE_MODEL,
            "text_response": None,
            "image_data": None
        }
        
        try:
            # Extract text and image data
            for part in response.candidates[0].content.parts:
                if hasattr(part, 'text') and part.text is not None:
                    result["text_response"] = part.text
                elif hasattr(part, 'inline_data') and part.inline_data is not None:
                    # Convert image data to base64
                    image_bytes = part.inline_data.data
                    result["image_data"] = base64.b64encode(image_bytes).decode('utf-8')
                    result["image_format"] = "png"  # Assuming PNG format
                    
                    # Save image dimensions
                    try:
                        img = PILImage.open(BytesIO(image_bytes))
                        result["width"] = img.width
                        result["height"] = img.height
                    except Exception:
                        pass
            
            # Check if we got an image
            if not result["image_data"]:
                return {"error": "No image was generated in the response"}
                
            return result
            
        except Exception as e:
            logger.error(f"Error processing Gemini response: {str(e)}")
            return {"error": f"Failed to process response: {str(e)}"}
    
    def _get_from_cache(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get result from cache if available
        
        Args:
            key: Cache key
            
        Returns:
            Optional[Dict]: Cached result or None
        """
        with self.cache_lock:
            if key in self.cache:
                entry = self.cache[key]
                # Check if entry is expired
                if time.time() < entry["expires_at"]:
                    return entry["data"]
                else:
                    # Remove expired entry
                    del self.cache[key]
        return None
    
    def _add_to_cache(self, key: str, data: Dict[str, Any], ttl: int = None):
        """
        Add result to cache
        
        Args:
            key: Cache key
            data: Data to cache
            ttl: Time-to-live in seconds
        """
        ttl = ttl or self.CACHE_EXPIRY
        
        with self.cache_lock:
            # Limit cache size
            if len(self.cache) >= self.MAX_CACHE_SIZE:
                # Remove oldest entry
                oldest_key = min(self.cache, key=lambda k: self.cache[k]["expires_at"])
                del self.cache[oldest_key]
            
            # Add new entry
            self.cache[key] = {
                "data": data,
                "expires_at": time.time() + ttl
            }
    
    def save_image_record(self, user_id: str, prompt: str, image_data: str, 
                        conversation_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Save generated image record to database
        
        Args:
            user_id: User ID
            prompt: Text prompt
            image_data: Base64-encoded image data
            conversation_id: Optional conversation ID
            
        Returns:
            Dict: Record information
        """
        db = get_db()
        
        # Generate unique ID for the image
        image_id = str(uuid.uuid4())
        
        # Create image record
        image_record = {
            "image_id": image_id,
            "user_id": user_id,
            "prompt": prompt,
            "conversation_id": conversation_id,
            "model": self.TEXT_TO_IMAGE_MODEL,
            "created_at": datetime.utcnow().isoformat()
        }
        
        try:
            # Store image metadata in database
            with db.get_connection() as conn:
                conn.execute(
                    """INSERT INTO images 
                    (image_id, user_id, prompt, conversation_id, model, created_at) 
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        image_id,
                        user_id,
                        prompt,
                        conversation_id,
                        self.TEXT_TO_IMAGE_MODEL,
                        image_record["created_at"]
                    )
                )
            
            # Store image data separately (could be in a blob store in production)
            # For this implementation, we'll save it in a local folder
            images_folder = os.path.join(current_app.instance_path, 'images')
            os.makedirs(images_folder, exist_ok=True)
            
            # Save image data
            image_binary = base64.b64decode(image_data)
            image_path = os.path.join(images_folder, f"{image_id}.png")
            with open(image_path, 'wb') as f:
                f.write(image_binary)
            
            return {
                "image_id": image_id,
                "success": True
            }
            
        except Exception as e:
            logger.error(f"Error saving image record: {str(e)}")
            return {
                "error": f"Failed to save image record: {str(e)}",
                "image_id": image_id
            }

# Initialize the image service
def get_image_service():
    """Get the image service instance"""
    if not hasattr(g, 'image_service'):
        g.image_service = ImageService()
    return g.image_service

# Routes
@images_bp.route('/generate', methods=['POST'])
def generate_image():
    """Generate image from text prompt
    
    Request body:
    {
        "prompt": "Text description of the image to generate",
        "conversation_id": "Optional conversation ID for context"
    }
    
    Returns:
        JSON response with image data
    """
    try:
        # Authenticate request
        if not hasattr(g, 'user') or not g.user:
            return jsonify({"error": "Authentication required"}), 401
        
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        prompt = data.get('prompt', '').strip()
        if not prompt:
            return jsonify({"error": "Prompt cannot be empty"}), 400
        
        conversation_id = data.get('conversation_id')
        
        # Get image service
        image_service = get_image_service()
        
        # Generate image
        result = image_service.generate_image_from_text(
            prompt=prompt,
            conversation_id=conversation_id,
            user_id=g.user["user_id"]
        )
        
        # Check for errors
        if "error" in result:
            return jsonify(result), 400
        
        # Save image record
        record_result = image_service.save_image_record(
            user_id=g.user["user_id"],
            prompt=prompt,
            image_data=result["image_data"],
            conversation_id=conversation_id
        )
        
        # Return the result
        return jsonify({
            "image_data": f"data:image/png;base64,{result['image_data']}",
            "text_response": result["text_response"],
            "width": result.get("width"),
            "height": result.get("height"),
            "image_id": record_result.get("image_id"),
            "timestamp": result["timestamp"]
        })
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Image generation error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred during image generation", "error_id": error_id}), 500

@images_bp.route('/edit', methods=['POST'])
def edit_image():
    """Edit an existing image based on text prompt
    
    Request body (multipart/form-data):
    - image: Image file to edit
    - prompt: Text description of the edits to make
    - conversation_id: Optional conversation ID for context
    
    Returns:
        JSON response with edited image data
    """
    try:
        # Authenticate request
        if not hasattr(g, 'user') or not g.user:
            return jsonify({"error": "Authentication required"}), 401
        
        # Check if image file was uploaded
        if 'image' not in request.files:
            return jsonify({"error": "No image file provided"}), 400
        
        image_file = request.files['image']
        if not image_file or image_file.filename == '':
            return jsonify({"error": "No image file selected"}), 400
        
        # Get prompt from form data
        prompt = request.form.get('prompt', '').strip()
        if not prompt:
            return jsonify({"error": "Prompt cannot be empty"}), 400
        
        conversation_id = request.form.get('conversation_id')
        
        # Read image data
        image_data = image_file.read()
        
        # Get image service
        image_service = get_image_service()
        
        # Edit image
        result = image_service.edit_image(
            image_data=image_data,
            prompt=prompt,
            user_id=g.user["user_id"]
        )
        
        # Check for errors
        if "error" in result:
            return jsonify(result), 400
        
        # Save image record
        record_result = image_service.save_image_record(
            user_id=g.user["user_id"],
            prompt=f"Edit: {prompt}",
            image_data=result["image_data"],
            conversation_id=conversation_id
        )
        
        # Return the result
        return jsonify({
            "image_data": f"data:image/png;base64,{result['image_data']}",
            "text_response": result["text_response"],
            "width": result.get("width"),
            "height": result.get("height"),
            "image_id": record_result.get("image_id"),
            "timestamp": result["timestamp"]
        })
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Image editing error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred during image editing", "error_id": error_id}), 500

@images_bp.route('/user/<user_id>', methods=['GET'])
def get_user_images(user_id):
    """Get images generated by a specific user
    
    Args:
        user_id: User ID
    
    Returns:
        JSON response with user's images
    """
    try:
        # Authenticate request
        if not hasattr(g, 'user') or not g.user:
            return jsonify({"error": "Authentication required"}), 401
        
        # Only allow users to see their own images (or admins to see any)
        if g.user["user_id"] != user_id and g.user["role"] != "admin":
            return jsonify({"error": "Access denied"}), 403
        
        # Support pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Get database service
        db = get_db()
        
        # Get images from database
        with db.get_connection() as conn:
            # Get total count
            total_count = conn.execute(
                "SELECT COUNT(*) as count FROM images WHERE user_id = ?",
                (user_id,)
            ).fetchone()["count"]
            
            # Get images with pagination
            rows = conn.execute(
                """SELECT image_id, prompt, conversation_id, model, created_at
                FROM images 
                WHERE user_id = ? 
                ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (user_id, per_page, (page - 1) * per_page)
            ).fetchall()
            
            # Build results
            images = []
            for row in rows:
                images.append({
                    "image_id": row["image_id"],
                    "prompt": row["prompt"],
                    "conversation_id": row["conversation_id"],
                    "model": row["model"],
                    "created_at": row["created_at"],
                    "thumbnail_url": f"/api/images/{row['image_id']}/thumbnail",
                    "image_url": f"/api/images/{row['image_id']}"
                })
            
            return jsonify({
                "images": images,
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
        logger.error(f"Get user images error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred retrieving images", "error_id": error_id}), 500

@images_bp.route('/<image_id>', methods=['GET'])
def get_image(image_id):
    """Get a specific image
    
    Args:
        image_id: Image ID
    
    Returns:
        The image file
    """
    try:
        # Authenticate request
        if not hasattr(g, 'user') or not g.user:
            return jsonify({"error": "Authentication required"}), 401
        
        # Get database service
        db = get_db()
        
        # Verify image exists and user has access
        with db.get_connection() as conn:
            image = conn.execute(
                "SELECT user_id FROM images WHERE image_id = ?",
                (image_id,)
            ).fetchone()
            
            # Check if image exists
            if not image:
                return jsonify({"error": "Image not found"}), 404
            
            # Check if user has access
            if image["user_id"] != g.user["user_id"] and g.user["role"] != "admin":
                return jsonify({"error": "Access denied"}), 403
        
        # Get image file path
        images_folder = os.path.join(current_app.instance_path, 'images')
        image_path = os.path.join(images_folder, f"{image_id}.png")
        
        # Check if file exists
        if not os.path.exists(image_path):
            return jsonify({"error": "Image file not found"}), 404
        
        # Return the image file
        return send_file(image_path, mimetype='image/png')
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Get image error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred retrieving the image", "error_id": error_id}), 500

@images_bp.route('/<image_id>/thumbnail', methods=['GET'])
def get_image_thumbnail(image_id):
    """Get a thumbnail of a specific image
    
    Args:
        image_id: Image ID
    
    Returns:
        The thumbnail image file
    """
    try:
        # Authenticate request
        if not hasattr(g, 'user') or not g.user:
            return jsonify({"error": "Authentication required"}), 401
        
        # Get database service
        db = get_db()
        
        # Verify image exists and user has access
        with db.get_connection() as conn:
            image = conn.execute(
                "SELECT user_id FROM images WHERE image_id = ?",
                (image_id,)
            ).fetchone()
            
            # Check if image exists
            if not image:
                return jsonify({"error": "Image not found"}), 404
            
            # Check if user has access
            if image["user_id"] != g.user["user_id"] and g.user["role"] != "admin":
                return jsonify({"error": "Access denied"}), 403
        
        # Get image file path
        images_folder = os.path.join(current_app.instance_path, 'images')
        image_path = os.path.join(images_folder, f"{image_id}.png")
        
        # Check if file exists
        if not os.path.exists(image_path):
            return jsonify({"error": "Image file not found"}), 404
        
        # Generate thumbnail path
        thumbnail_folder = os.path.join(current_app.instance_path, 'thumbnails')
        os.makedirs(thumbnail_folder, exist_ok=True)
        thumbnail_path = os.path.join(thumbnail_folder, f"{image_id}.png")
        
        # Generate thumbnail if it doesn't exist
        if not os.path.exists(thumbnail_path):
            try:
                img = PILImage.open(image_path)
                img.thumbnail((200, 200))
                img.save(thumbnail_path)
            except Exception as thumb_error:
                logger.error(f"Error generating thumbnail: {str(thumb_error)}")
                # Fall back to original image
                thumbnail_path = image_path
        
        # Return the thumbnail file
        return send_file(thumbnail_path, mimetype='image/png')
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Get thumbnail error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred retrieving the thumbnail", "error_id": error_id}), 500

# Database schema initialization - independent of application context
def create_image_tables(db_service: DatabaseService) -> None:
    """Create database tables for image storage (context-independent)
    
    Args:
        db_service: Database service instance
    """
    with db_service.get_connection() as conn:
        # Images table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS images (
            image_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            prompt TEXT NOT NULL,
            conversation_id TEXT,
            model TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id),
            FOREIGN KEY (conversation_id) REFERENCES conversations (conversation_id) ON DELETE SET NULL
        )
        ''')
        
        # Create index for faster user image lookup
        conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_images_user_id ON images (user_id, created_at)
        ''')
    
    logger.info("Image database tables initialized")

# Register the blueprint with the Flask app
def register_blueprint(app):
    """Register the images blueprint with the Flask app"""
    app.register_blueprint(images_bp)
    
    # Initialize tables with a proper application context
    with app.app_context():
        try:
            db_path = app.config.get("DATABASE_PATH", "triton.db")
            db_service = DatabaseService(db_path, app.config)
            create_image_tables(db_service)
        except Exception as e:
            logger.error(f"Failed to initialize image database tables: {str(e)}")
    
    logger.info("Image routes registered")
