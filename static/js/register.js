/**
 * Registration functionality for Triton AI
 * Handles user registration with invitation validation
 */
function registerApp() {
    return {
        // Form fields
        username: '',
        email: '',
        password: '',
        confirmPassword: '',
        invitationToken: '',
        termsAgreed: false,
        
        // UI states
        isLoading: false,
        error: null,
        success: null,
        showPassword: false,
        showConfirmPassword: false,
        
        // Password strength
        passwordScore: 0,
        passwordStrength: '',
        
        // Invitation validation
        isValidatingInvitation: false,
        isInvitationValid: false,
        
        initialize() {
            // Check if user is already logged in
            const authService = window.authService ? window.authService() : null;
            if (authService && authService.isLoggedIn()) {
                window.location.href = '/';
                return;
            }
            
            // Get invitation parameters from URL
            const urlParams = new URLSearchParams(window.location.search);
            const email = urlParams.get('email');
            const token = urlParams.get('token');
            
            if (email && token) {
                this.email = email;
                this.invitationToken = token;
                
                // Email is read-only when provided by invitation
                document.getElementById('email').readOnly = true;
                
                this.validateInvitation();
            }
        },
        
        async validateInvitation() {
            if (!this.email || !this.invitationToken) return;
            
            this.isValidatingInvitation = true;
            this.error = null;
            
            try {
                const response = await fetch('/auth/validate-invitation', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: this.email,
                        token: this.invitationToken
                    })
                });
                
                const data = await response.json();
                
                if (response.ok && data.valid) {
                    this.isInvitationValid = true;
                } else {
                    this.error = data.error || 'Invalid or expired invitation link';
                    this.isInvitationValid = false;
                }
            } catch (error) {
                console.error('Error validating invitation:', error);
                this.error = 'Failed to validate invitation';
                this.isInvitationValid = false;
            } finally {
                this.isValidatingInvitation = false;
            }
        },
        
        checkPasswordStrength() {
            let score = 0;
            
            // Check length
            if (this.password.length >= 8) score++;
            if (this.password.length >= 12) score++;
            
            // Check for lowercase letters
            if (/[a-z]/.test(this.password)) score++;
            
            // Check for uppercase letters
            if (/[A-Z]/.test(this.password)) score++;
            
            // Check for numbers
            if (/[0-9]/.test(this.password)) score++;
            
            // Check for special characters
            if (/[^A-Za-z0-9]/.test(this.password)) score++;
            
            // Update score and strength
            this.passwordScore = score;
            
            if (score <= 2) {
                this.passwordStrength = 'weak';
            } else if (score <= 4) {
                this.passwordStrength = 'medium';
            } else {
                this.passwordStrength = 'strong';
            }
        },
        
        togglePasswordVisibility() {
            this.showPassword = !this.showPassword;
        },
        
        toggleConfirmPasswordVisibility() {
            this.showConfirmPassword = !this.showConfirmPassword;
        },
        
        get isFormValid() {
            return (
                this.username.trim().length >= 3 &&
                this.email.trim().length > 0 &&
                this.isValidEmail(this.email) &&
                this.password.length >= 8 &&
                this.password === this.confirmPassword &&
                this.passwordScore >= 3 &&
                this.termsAgreed &&
                this.invitationToken.length > 0
            );
        },
        
        isValidEmail(email) {
            const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
            return re.test(String(email).toLowerCase());
        },
        
        async register() {
            if (!this.isFormValid) return;
            
            this.isLoading = true;
            this.error = null;
            this.success = null;
            
            try {
                const response = await fetch('/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: this.username,
                        email: this.email,
                        password: this.password,
                        invitation_token: this.invitationToken
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    this.success = 'Registration successful! Redirecting to dashboard...';
                    
                    if (data.token) {
                        localStorage.setItem('auth_token', data.token);
                    }
                    
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 1500);
                } else {
                    this.error = data.error || 'Registration failed';
                }
            } catch (error) {
                console.error('Registration error:', error);
                this.error = 'An unexpected error occurred';
            } finally {
                this.isLoading = false;
            }
        },
        
        getPasswordStrengthClass() {
            if (this.passwordStrength === 'weak') return 'bg-danger-500';
            if (this.passwordStrength === 'medium') return 'bg-warning-500';
            if (this.passwordStrength === 'strong') return 'bg-success-500';
            return 'bg-secondary-200';
        },
        
        getPasswordStrengthLabel() {
            if (!this.password) return '';
            if (this.passwordStrength === 'weak') return 'Weak password';
            if (this.passwordStrength === 'medium') return 'Medium password';
            if (this.passwordStrength === 'strong') return 'Strong password';
            return '';
        }
    };
}
