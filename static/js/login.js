function loginApp() {
    return {
        email: '',
        password: '',
        error: null,
        isLoading: false,
        rememberMe: false,
        showPassword: false,
        
        initialize() {
            // Check if user is already logged in
            const authService = window.authService ? window.authService() : null;
            if (authService && authService.isLoggedIn()) {
                window.location.href = '/';
            }
            
            // Check for saved email in localStorage
            const savedEmail = localStorage.getItem('rememberedEmail');
            if (savedEmail) {
                this.email = savedEmail;
                this.rememberMe = true;
            }
        },
        
        togglePasswordVisibility() {
            this.showPassword = !this.showPassword;
        },
        
        get isFormValid() {
            return (
                this.email.trim().length > 0 &&
                this.password.length > 0
            );
        },
        
        async login() {
            if (!this.isFormValid) return;
            
            this.isLoading = true;
            this.error = null;
            
            try {
                const authService = window.authService ? window.authService() : null;
                
                if (!authService) {
                    throw new Error('Authentication service not available');
                }
                
                const result = await authService.login(this.email, this.password);
                
                if (result.success) {
                    // Save email in localStorage if remember me is checked
                    if (this.rememberMe) {
                        localStorage.setItem('rememberedEmail', this.email);
                    } else {
                        localStorage.removeItem('rememberedEmail');
                    }
                    
                    // Redirect to home page
                    window.location.href = '/';
                } else {
                    this.error = result.error;
                }
            } catch (error) {
                console.error('Login error:', error);
                this.error = 'An unexpected error occurred. Please try again.';
            } finally {
                this.isLoading = false;
            }
        },
        
        handleKeyDown(event) {
            if (event.key === 'Enter' && this.isFormValid && !this.isLoading) {
                this.login();
            }
        }
    };
}
