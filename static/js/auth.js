/**
 * Authentication Service for Triton AI
 * Handles user authentication, session management and token storage
 */
function authService() {
    return {
        /**
         * Check if user is currently logged in
         * @returns {boolean} Login status
         */
        isLoggedIn() {
            return !!localStorage.getItem('auth_token');
        },
        
        /**
         * Check authentication status with server
         * @returns {Promise<Object>} Authentication status and user info
         */
        async checkAuthStatus() {
            try {
                const token = localStorage.getItem('auth_token');
                if (!token) {
                    return { isAuthenticated: false };
                }
                
                const response = await fetch('/auth/me', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    return {
                        isAuthenticated: true,
                        user: data.user
                    };
                } else {
                    localStorage.removeItem('auth_token');
                    return { isAuthenticated: false };
                }
            } catch (error) {
                console.error('Auth check error:', error);
                return { isAuthenticated: false, error: error.message };
            }
        },
        
        /**
         * Log in user with email and password
         * @param {string} email - User email
         * @param {string} password - User password
         * @returns {Promise<Object>} Login result
         */
        async login(email, password) {
            try {
                const response = await fetch('/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Store the token
                    localStorage.setItem('auth_token', data.token);
                    return {
                        success: true,
                        user: data.user
                    };
                } else {
                    return {
                        success: false,
                        error: data.error || 'Login failed'
                    };
                }
            } catch (error) {
                console.error('Login error:', error);
                return {
                    success: false,
                    error: 'Network error occurred'
                };
            }
        },
        
        /**
         * Register a new user
         * @param {Object} userData - User registration data
         * @returns {Promise<Object>} Registration result
         */
        async register(userData) {
            try {
                const response = await fetch('/auth/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(userData)
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Store the token
                    localStorage.setItem('auth_token', data.token);
                    return {
                        success: true,
                        user: data.user
                    };
                } else {
                    return {
                        success: false,
                        error: data.error || 'Registration failed'
                    };
                }
            } catch (error) {
                console.error('Registration error:', error);
                return {
                    success: false,
                    error: 'Network error occurred'
                };
            }
        },
        
        /**
         * Log out the current user
         * @returns {Promise<Object>} Logout result
         */
        async logout() {
            try {
                const token = localStorage.getItem('auth_token');
                if (!token) {
                    return { success: true };
                }
                
                const response = await fetch('/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                
                // Remove the token regardless of server response
                localStorage.removeItem('auth_token');
                
                if (response.ok) {
                    return { success: true };
                } else {
                    const data = await response.json();
                    return {
                        success: true, // Still consider it successful since we removed the token
                        warning: data.error || 'Server logout failed, but local logout succeeded'
                    };
                }
            } catch (error) {
                console.error('Logout error:', error);
                // Still remove the token on client side
                localStorage.removeItem('auth_token');
                return {
                    success: true,
                    warning: 'Network error occurred, but local logout succeeded'
                };
            }
        },
        
        /**
         * Verify an invitation token
         * @param {string} email - Invited email
         * @param {string} token - Invitation token
         * @returns {Promise<Object>} Verification result
         */
        async verifyInvitation(email, token) {
            try {
                const response = await fetch('/auth/validate-invitation', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email, token })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    return {
                        success: true,
                        verified: true
                    };
                } else {
                    return {
                        success: false,
                        verified: false,
                        error: data.error || 'Invitation verification failed'
                    };
                }
            } catch (error) {
                console.error('Invitation verification error:', error);
                return {
                    success: false,
                    verified: false,
                    error: 'Network error occurred'
                };
            }
        }
    };
}

/**
 * Fetch available models from the API
 * @returns {Promise<Object>} Model data from the API
 */
async function fetchAvailableModels() {
    try {
        const response = await fetch('/models', {
            method: 'GET',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            return await response.json();
        } else {
            console.error('Failed to fetch models from API');
            return { models: {} };
        }
    } catch (error) {
        console.error('Error fetching models:', error);
        return { models: {} };
    }
}
