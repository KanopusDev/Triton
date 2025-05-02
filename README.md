# Triton AI

![Triton AI](./static/icons/logo.svg)

## Enterprise-Grade AI Assistant Platform

Triton AI is a secure, scalable, and feature-rich AI assistant platform designed for enterprise use. Leveraging state-of-the-art language models with enhanced capabilities including real-time web search, multi-step reasoning, document processing, and deep research capabilities.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-2.0%2B-green)](https://flask.palletsprojects.com/)

## Table of Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Security](#security)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Administration](#administration)
- [Development](#development)
- [License](#license)

## Key Features

### Core Capabilities
- **Multiple AI Models**: Support for various AI providers (OpenAI, Microsoft, Anthropic, Meta, Cohere)
- **Web Search Integration**: Real-time information retrieval with source citation
- **Step-by-Step Reasoning**: Transparent AI reasoning process visualization
- **Deep Research**: Multi-step web research with content extraction and synthesis
- **Document Processing**: Upload and analyze documents with AI assistance

### Enterprise Features
- **Role-Based Access Control**: Granular user permissions (Admin, User)
- **Invitation System**: Secure user onboarding via email invitations
- **Comprehensive Logging**: Detailed system activity monitoring
- **Admin Dashboard**: Usage analytics, user management, and system configuration
- **Conversation History**: Persistent storage of all interactions
- **API Access**: JWT-based authentication for programmatic access

## Architecture

Triton AI is built on a modern, scalable architecture:

- **Backend**: Python Flask application with SQLite database (PostgreSQL ready)
- **Frontend**: Alpine.js with Tailwind CSS for responsive UI
- **AI Integration**: Azure AI and OpenAI API integrations
- **Authentication**: JWT token and session-based auth system
- **File Storage**: Secure document management system

## Security

Security is a core design consideration:

- **Authentication**: Secure cookie-based sessions with JWT token support
- **Password Security**: bcrypt hashing with appropriate work factors
- **CSRF Protection**: Cross-Site Request Forgery prevention
- **Content Security Policy**: Strict CSP implementation
- **Rate Limiting**: Protection against abuse and API flooding
- **Input Validation**: Thorough sanitization of all inputs
- **Secure Headers**: Implementation of security-focused HTTP headers
- **Role Enforcement**: Strict permission checks on all endpoints

## Installation

### Prerequisites
- Python 3.9+
- pip (Python package manager)
- Node.js and npm (for frontend development)
- Git

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/triton.git
   cd triton
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration settings
   ```

5. Initialize the database:
   ```bash
   flask init-db
   ```

6. Create an admin user:
   ```bash
   flask create-admin --username admin --email admin@example.com --password secure_password
   ```

7. Run the application:
   ```bash
   flask run
   # For production: gunicorn -w 4 -b 0.0.0.0:8000 main:app
   ```

## Configuration

Triton AI is configured via environment variables in the `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Application secret key for sessions | Auto-generated |
| `AZURE_API_KEY` | Azure OpenAI API key | Required |
| `GITHUB_TOKEN` | GitHub AI token (if using GitHub models) | Optional |
| `DATABASE_PATH` | SQLite database location | `triton.db` |
| `UPLOAD_FOLDER` | Document upload directory | `uploads` |
| `DEBUG` | Enable debug mode | `false` |
| `LOG_LEVEL` | Logging verbosity | `INFO` |
| `CORS_ORIGINS` | Allowed CORS origins | `*` |
| `SESSION_COOKIE_SECURE` | Require HTTPS for cookies | `true` |

## Usage

### Web Interface

1. Navigate to `http://localhost:5000` (or your deployed URL)
2. Log in with your credentials
3. Start a new conversation
4. Select AI model and enable desired features (Search, Reasoning, etc.)
5. Begin chatting with the AI assistant

### API Access

Triton provides a RESTful API with JWT authentication:

```bash
# Authenticate and get token
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"your_password"}'

# Use token for API requests
curl -X POST http://localhost:5000/chat \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"Hello, Triton AI","model":"openai/gpt-4o","features":{"search":true}}'
```

## API Documentation

### Authentication Endpoints

- **POST /auth/login**: Authenticate user and get session/token
- **POST /auth/logout**: End user session
- **GET /auth/me**: Get current user info
- **POST /auth/register**: Register new user (requires invitation)
- **POST /auth/invite**: Create invitation for new user

### Conversation Endpoints

- **GET /conversations**: List user conversations
- **GET /conversations/:id**: Get specific conversation and messages
- **PATCH /conversations/:id**: Update conversation properties
- **DELETE /conversations/:id**: Delete a conversation

### Chat Endpoints

- **POST /chat**: Send message and get AI response
- **GET /models**: List available AI models

## Administration

Triton includes a comprehensive admin panel at `/admin`:

- **User Management**: Create, edit, and deactivate users
- **Analytics Dashboard**: Usage statistics and activity monitoring
- **Invitation Management**: Track and manage user invitations
- **System Configuration**: Adjust application settings
- **Document Management**: View and manage uploaded documents
- **System Logs**: Monitor application activity and errors

## Development

### Project Structure

```
triton/
├── main.py              # Application entry point
├── static/              # Static assets
│   ├── css/             # Stylesheets
│   ├── js/              # JavaScript files
│   └── icons/           # Icons and images
├── templates/           # HTML templates
├── uploads/             # Document storage
└── tests/               # Unit and integration tests
```

### Running Tests

```bash
pytest
```

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

© 2024 Triton AI. All rights reserved.

For support, contact: contact@kanopus.org