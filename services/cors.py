from flask import Flask
from flask_cors import CORS

class CorsService:
    """Service for configuring CORS and security headers for Flask applications"""
    
    @staticmethod
    def initialize(app: Flask, origins: list = None, credentials: bool = True) -> None:
        """
        Initialize CORS for a Flask application
        
        Args:
            app: Flask application instance
            origins: List of allowed origins (defaults to value from app config)
            credentials: Whether to support credentials
        """
        origins = origins or app.config.get("CORS_ORIGINS", "*")
        
        # Configure CORS
        CORS(app, 
             origins=origins,
             supports_credentials=credentials)
        
        # Register the after_request handler
        @app.after_request
        def add_security_headers(response):
            """Add security headers to all responses"""
            # CORS headers
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With')
            response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            
            # Security headers
            response.headers.add('X-Content-Type-Options', 'nosniff')
            response.headers.add('X-Frame-Options', 'DENY')
            response.headers.add('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
            
            # Content Security Policy
            csp_directives = CorsService._get_csp_directives()
            response.headers.add('Content-Security-Policy', "; ".join(csp_directives))
            
            return response

    @staticmethod
    def _get_csp_directives() -> list:
        """Get Content Security Policy directives
        
        Returns:
            list: List of CSP directives
        """
        return [
            "default-src 'self'",
            "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com https://static.cloudflareinsights.com 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
            "connect-src 'self' https://cloudflareinsights.com"
        ]

    @staticmethod
    def configure_cache_headers(app: Flask) -> None:
        """
        Configure cache-related routes and headers
        
        Args:
            app: Flask application instance
        """
        # Add route for serving font files with proper cache headers
        @app.route('/static/fonts/<path:filename>')
        def serve_font(filename):
            """Serve font files with proper cache headers"""
            response = app.send_static_file(f'fonts/{filename}')
            # Cache fonts for 1 year (far future expiry)
            response.headers['Cache-Control'] = 'public, max-age=31536000'
            return response
