# Triton AI Platform

<div align="center">
  <img src="static/icons/logo.svg" alt="Triton AI Logo" width="120" height="120">
  <h3>Enterprise-Grade AI Assistant Platform</h3>
  <p>A secure, scalable, and feature-rich AI conversation platform with advanced knowledge retrieval capabilities</p>

  ![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
  ![License](https://img.shields.io/badge/License-Proprietary-red)
  ![Version](https://img.shields.io/badge/Version-1.0.0-green)
  ![Status](https://img.shields.io/badge/Status-Production-success)
</div>

---

## Overview

Triton AI is an enterprise-grade conversational AI platform that provides secure access to multiple large language models (LLMs) with enhanced capabilities like web search, document processing, deep research, and reasoning explanations. Built with security and performance at its core, Triton AI delivers a comprehensive solution for organizations seeking advanced AI assistance while maintaining full control over their data and user access.

### Key Features

- **Multi-Model Access**: Seamlessly switch between models from OpenAI, Microsoft, Meta, Cohere, and more
- **Web Search Integration**: Obtain real-time information from the web with source citation
- **Deep Research Mode**: Perform multi-step web research with automatic content extraction
- **Document Processing**: Upload and analyze documents with contextual queries
- **Reasoning Transparency**: View step-by-step reasoning processes behind AI responses
- **Enterprise Security**: Role-based access control, secure authentication, and comprehensive audit logs
- **Admin Dashboard**: Complete administrator controls for user management and system monitoring

## System Requirements

- **Python**: 3.10 or higher
- **OS**: Linux (recommended), macOS, or Windows
- **Storage**: Minimum 2GB for application, varies based on document storage needs
- **Memory**: Minimum 4GB RAM, 8GB+ recommended for production
- **Database**: SQLite (included), compatible with PostgreSQL for enterprise deployment
- **Network**: Reliable internet connection for external model and web search access

## Installation

### Using Docker (Recommended for Production)

```bash
# Clone the repository
git clone https://github.com/gamecooler19/triton.git
cd triton

# Build and start the Docker containers
docker-compose up -d
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/gamecooler19/triton.git
cd triton

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Initialize the database and create an admin user
flask create-admin --username admin --email admin@example.com --password secure_password

# Start the application
python main.py
```

## Configuration

### Environment Variables

Triton AI is configured primarily through environment variables. These can be set in a `.env` file in the project root:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Cryptographic key for sessions | Auto-generated | No |
| `AZURE_API_KEY` | Azure OpenAI API Key | None | Yes |
| `GITHUB_TOKEN` | GitHub token for model access | None | Yes |
| `GOOGLE_API_KEY` | Google API Key for search | None | Yes |
| `GOOGLE_SEARCH_ENGINE_ID` | Google Search Engine ID | None | Yes |
| `DATABASE_PATH` | SQLite database location | `triton.db` | No |
| `UPLOAD_FOLDER` | Path for uploaded documents | `uploads` | No |
| `MAX_UPLOAD_SIZE` | Max document size in MB | `50` | No |
| `LOG_LEVEL` | Logging verbosity | `INFO` | No |
| `PORT` | Server port | `5000` | No |
| `DEBUG` | Enable debug mode | `false` | No |
| `SESSION_COOKIE_SECURE` | Require HTTPS for cookies | `true` | No |
| `CORS_ORIGINS` | Allowed CORS origins | `*` | No |

### Authentication

Triton AI uses a robust multi-layered authentication system:

1. **Session-based authentication** for web interface
2. **JWT token authentication** for API access
3. **Invitation-only registration** to control user access

## Administration

### Creating the First Admin User

```bash
flask create-admin --username admin --email admin@example.com --password secure_password
```

### Admin Dashboard

The administration dashboard is accessible at `/admin` for users with admin privileges and provides:

- User management
- System statistics and monitoring
- Document management
- Invitation administration
- System logs and configuration

## Security Considerations

- All passwords are hashed using bcrypt with appropriate work factors
- Session cookies are HTTP-only and secure by default
- Content Security Policy (CSP) is configured to prevent XSS attacks
- API rate limiting is implemented to prevent abuse
- Database queries use parameterized statements to prevent SQL injection
- Input validation is performed for all user-provided data
- Role-based access control limits user permissions

## API Documentation

Triton AI provides a RESTful API for integration with other systems. Authentication uses JWT tokens obtained via the `/auth/login` endpoint.

### Key Endpoints

- **Authentication**: `/auth/*` - Login, registration, user management
- **Conversations**: `/conversations/*` - CRUD operations for conversations
- **Chat**: `/chat` - Send messages and receive AI responses
- **Models**: `/models` - List available AI models
- **Admin**: `/admin/*` - Administrative functions

Full API documentation is available in the [API.md](docs/API.md) file.

## Development

### Project Structure

```
triton/
├── main.py             # Main application entry point
├── static/             # Static assets
│   ├── css/            # Stylesheets
│   ├── js/             # JavaScript files
│   └── icons/          # Images and icons
├── templates/          # HTML templates
├── uploads/            # Document storage
├── docs/               # Documentation
├── requirements.txt    # Python dependencies
├── .env.example        # Example environment variables
└── README.md           # This file
```

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Run linting
flake8 .

# Format code
black .
```

## Deployment

### Production Recommendations

1. **Use HTTPS**: Always deploy behind HTTPS in production
2. **Database**: Consider PostgreSQL for high-volume deployments
3. **Reverse Proxy**: Use Nginx or similar as a reverse proxy
4. **Monitoring**: Implement monitoring and alerting
5. **Backups**: Regular database backups
6. **Rate Limiting**: Configure appropriate rate limits

### Docker Deployment

```bash
# Production deployment with Docker
docker-compose -f docker-compose.prod.yml up -d
```

## Troubleshooting

### Common Issues

- **Authentication Failures**: Check session configuration and cookie settings
- **Model API Errors**: Verify API keys and endpoint configuration
- **Performance Issues**: Check server resources and database indexing

### Logs

Application logs are stored in `triton.log` by default and include detailed information about application activity and errors.

## License

Triton AI is proprietary software. All rights reserved.

© 2024 Triton AI

## Contact

For support or inquiries, contact:

- **Technical Support**: support@kanopus.org
- **Security Issues**: support@kanopus.org