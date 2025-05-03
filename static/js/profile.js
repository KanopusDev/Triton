function profileApp() {
    return {
        isAuthenticated: false,
        isCheckingAuth: true,
        profileSection: 'personal',
        isLoading: false,
        
        // User data
        userName: '',
        userEmail: '',
        userRole: '',
        userInitials: '',
        
        // Form data
        errorMessage: null,
        successMessage: null,
        
        // Profile fields
        profileInfo: {
            fullName: '',
            bio: '',
            jobTitle: '',
            company: '',
            location: '',
            website: '',
            avatar: null
        },
        
        // API keys
        apiKeys: [],
        isGeneratingKey: false,
        newKeyName: '',
        keyToDelete: null,
        showDeleteKeyModal: false,
        
        // Advanced settings
        advancedSettings: {
            codeTheme: 'github',
            messageLayout: 'comfortable',
            telemetry: true
        },
        
        async initialize() {
            await this.checkAuthStatus();
            if (this.isAuthenticated) {
                await this.loadUserData();
                await this.loadProfileInfo();
                await this.loadApiKeys();
                await this.loadAdvancedSettings();
                
                // Check URL parameters for section selection
                const urlParams = new URLSearchParams(window.location.search);
                const section = urlParams.get('section');
                if (section && ['personal', 'apiKeys', 'advanced'].includes(section)) {
                    this.profileSection = section;
                }
            }
        },
        
        async checkAuthStatus() {
            try {
                this.isCheckingAuth = true;
                const authService = window.authService ? window.authService() : null;
                
                if (!authService) {
                    console.error('Auth service not available');
                    this.isAuthenticated = false;
                    return;
                }
                
                const result = await authService.checkAuthStatus();
                this.isAuthenticated = result.isAuthenticated;
                
                if (!this.isAuthenticated) {
                    window.location.href = '/login';
                }
            } catch (error) {
                console.error('Error checking auth status:', error);
                this.isAuthenticated = false;
            } finally {
                this.isCheckingAuth = false;
            }
        },
        
        async loadUserData() {
            try {
                const response = await fetch('/auth/me', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    const user = data.user;
                    
                    this.userName = user.username;
                    this.userEmail = user.email;
                    this.userRole = user.role;
                    
                    // Generate initials from name
                    this.userInitials = this.userName
                        .split(' ')
                        .map(word => word[0])
                        .join('')
                        .toUpperCase()
                        .substring(0, 2);
                }
            } catch (error) {
                console.error('Error loading user data:', error);
            }
        },
        
        async loadProfileInfo() {
            try {
                // In a real application, you would fetch profile information from the server
                // For this example, we'll use localStorage
                const savedProfileInfo = localStorage.getItem('profileInfo');
                if (savedProfileInfo) {
                    this.profileInfo = JSON.parse(savedProfileInfo);
                } else {
                    // Initialize with username if no profile exists
                    this.profileInfo.fullName = this.userName;
                }
            } catch (error) {
                console.error('Error loading profile info:', error);
            }
        },
        
        async loadApiKeys() {
            try {
                // In a real application, you would fetch API keys from the server
                // For now, we'll use localStorage for persistence
                const savedApiKeys = localStorage.getItem('apiKeys');
                if (savedApiKeys) {
                    this.apiKeys = JSON.parse(savedApiKeys);
                } else {
                    this.apiKeys = [];
                }
            } catch (error) {
                console.error('Error loading API keys:', error);
            }
        },
        
        async loadAdvancedSettings() {
            try {
                // Load advanced settings from localStorage
                const savedSettings = localStorage.getItem('advancedSettings');
                if (savedSettings) {
                    this.advancedSettings = { ...this.advancedSettings, ...JSON.parse(savedSettings) };
                }
            } catch (error) {
                console.error('Error loading advanced settings:', error);
            }
        },
        
        async saveProfileInfo() {
            this.clearMessages();
            this.isLoading = true;
            
            try {
                // In a real application, you would send profile info to the server
                // For now, we'll use localStorage for persistence
                localStorage.setItem('profileInfo', JSON.stringify(this.profileInfo));
                
                this.successMessage = 'Profile information saved successfully';
                
                // Hide success message after a delay
                setTimeout(() => {
                    this.successMessage = null;
                }, 3000);
            } catch (error) {
                console.error('Error saving profile info:', error);
                this.errorMessage = 'Failed to save profile information';
            } finally {
                this.isLoading = false;
            }
        },
        
        async generateApiKey() {
            if (!this.newKeyName.trim()) {
                this.errorMessage = 'Key name is required';
                return;
            }
            
            this.clearMessages();
            this.isGeneratingKey = true;
            
            try {
                // In a real application, you would request an API key from the server
                // For now, we'll generate a fake key
                const keyPrefix = 'trt_';
                const keyChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
                let key = keyPrefix;
                
                for (let i = 0; i < 32; i++) {
                    key += keyChars.charAt(Math.floor(Math.random() * keyChars.length));
                }
                
                const newKey = {
                    id: Date.now().toString(),
                    name: this.newKeyName.trim(),
                    key: key,
                    created: new Date().toISOString(),
                    last_used: null
                };
                
                this.apiKeys.push(newKey);
                localStorage.setItem('apiKeys', JSON.stringify(this.apiKeys));
                
                this.newKeyName = '';
                this.successMessage = 'API key generated successfully';
                
                // Hide success message after a delay
                setTimeout(() => {
                    this.successMessage = null;
                }, 3000);
                
                return newKey;
            } catch (error) {
                console.error('Error generating API key:', error);
                this.errorMessage = 'Failed to generate API key';
            } finally {
                this.isGeneratingKey = false;
            }
        },
        
        confirmDeleteKey(keyId) {
            this.keyToDelete = keyId;
            this.showDeleteKeyModal = true;
        },
        
        async deleteApiKey() {
            if (!this.keyToDelete) return;
            
            try {
                // In a real application, you would delete the API key on the server
                // For now, we'll just remove it from the local array
                this.apiKeys = this.apiKeys.filter(key => key.id !== this.keyToDelete);
                localStorage.setItem('apiKeys', JSON.stringify(this.apiKeys));
                
                this.successMessage = 'API key deleted successfully';
                
                // Hide success message after a delay
                setTimeout(() => {
                    this.successMessage = null;
                }, 3000);
            } catch (error) {
                console.error('Error deleting API key:', error);
                this.errorMessage = 'Failed to delete API key';
            } finally {
                this.showDeleteKeyModal = false;
                this.keyToDelete = null;
            }
        },
        
        copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                dispatchNotification('Copied to clipboard', 'info');
            }).catch(err => {
                console.error('Failed to copy: ', err);
                dispatchNotification('Failed to copy to clipboard', 'error');
            });
        },
        
        saveSettings() {
            try {
                localStorage.setItem('advancedSettings', JSON.stringify(this.advancedSettings));
                dispatchNotification('Settings saved successfully', 'success');
            } catch (error) {
                console.error('Error saving settings:', error);
                dispatchNotification('Failed to save settings', 'error');
            }
        },
        
        clearMessages() {
            this.errorMessage = null;
            this.successMessage = null;
        },
        
        formatDate(dateString) {
            return DateFormatter.formatDateTime(dateString, {
                monthFormat: 'long'
            });
        }
    };
}
