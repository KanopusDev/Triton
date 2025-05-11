function settingsApp() {
    return {
        isAuthenticated: false,
        isCheckingAuth: true,
        userName: '',
        userEmail: '',
        userInitials: '',
        settingsSection: 'account',
        isUpdating: false,
        isExporting: false,
        errorMessage: null,
        successMessage: null,
        passwordScore: 0,
        passwordStrength: '',
        
        // Account settings
        accountSettings: {
            username: '',
            email: '',
            timezone: 'UTC',
            language: 'en'
        },
        
        // Security settings
        securitySettings: {
            currentPassword: '',
            newPassword: '',
            confirmPassword: ''
        },
        
        // Sessions
        sessions: [],
        
        // Notification settings
        notificationSettings: {
            emailEnabled: true,
            systemAnnouncements: true,
            securityAlerts: true,
            newFeatures: true,
            tips: false,
            browserEnabled: false,
            digestFrequency: 'weekly'
        },
        
        // Appearance settings
        appearanceSettings: {
            theme: 'system',
            textSize: 100,
            chatLayout: 'default'
        },
        
        // Data settings
        dataSettings: {
            telemetry: true
        },
        
        // Confirmation modal
        confirmModal: {
            show: false,
            title: '',
            message: '',
            type: '',
            confirmText: 'Confirm',
            input: '',
            callback: null
        },
        
        async initialize() {
            await this.checkAuthStatus();
            if (this.isAuthenticated) {
                await this.loadUserData();
                await this.loadSettings();
                await this.loadSessions();
                
                // Check URL parameters for section selection
                const urlParams = new URLSearchParams(window.location.search);
                const section = urlParams.get('section');
                if (section && ['account', 'security', 'notifications', 'appearance', 'data'].includes(section)) {
                    this.settingsSection = section;
                }
            }
        },
        
        async checkAuthStatus() {
            try {
                this.isCheckingAuth = true;
                const response = await fetch('/auth/me', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.isAuthenticated = true;
                } else {
                    this.isAuthenticated = false;
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
                    
                    // Set account settings from user data
                    this.accountSettings.username = user.username;
                    this.accountSettings.email = user.email;
                    
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
        
        async loadSettings() {
            // In a real application, you would fetch user settings from the server
            // For now, we'll use localStorage for persistence
            
            // Load account settings
            const savedAccountSettings = localStorage.getItem('accountSettings');
            if (savedAccountSettings) {
                try {
                    const parsedSettings = JSON.parse(savedAccountSettings);
                    // Keep email and username from the user data, but use saved timezone and language
                    this.accountSettings = { 
                        ...this.accountSettings,
                        timezone: parsedSettings.timezone || 'UTC',
                        language: parsedSettings.language || 'en'
                    };
                } catch (error) {
                    console.error('Error parsing saved account settings:', error);
                }
            }
            
            // Load notification settings
            const savedNotificationSettings = localStorage.getItem('notificationSettings');
            if (savedNotificationSettings) {
                try {
                    const parsedSettings = JSON.parse(savedNotificationSettings);
                    this.notificationSettings = { ...this.notificationSettings, ...parsedSettings };
                } catch (error) {
                    console.error('Error parsing saved notification settings:', error);
                }
            }
            
            // Load appearance settings
            const savedAppearanceSettings = localStorage.getItem('appearanceSettings');
            if (savedAppearanceSettings) {
                try {
                    const parsedSettings = JSON.parse(savedAppearanceSettings);
                    this.appearanceSettings = { ...this.appearanceSettings, ...parsedSettings };
                    
                    // Apply the saved theme
                    this.applyTheme(this.appearanceSettings.theme);
                    
                    // Apply the saved text size
                    this.applyTextSize(this.appearanceSettings.textSize);
                } catch (error) {
                    console.error('Error parsing saved appearance settings:', error);
                }
            }
            
            // Load data settings
            const savedDataSettings = localStorage.getItem('dataSettings');
            if (savedDataSettings) {
                try {
                    const parsedSettings = JSON.parse(savedDataSettings);
                    this.dataSettings = { ...this.dataSettings, ...parsedSettings };
                } catch (error) {
                    console.error('Error parsing saved data settings:', error);
                }
            }
        },
        
        async loadSessions() {
            try {
                // This would be a real API call in a production app
                // For now, we'll simulate with fake data
                
                // Get the current session's user agent
                const currentUserAgent = navigator.userAgent;
                
                this.sessions = [
                    {
                        id: 'current-session',
                        userAgent: currentUserAgent,
                        location: 'Current Location',
                        lastActive: new Date().toISOString(),
                        current: true
                    },
                    {
                        id: 'session-1',
                        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
                        location: 'New York, USA',
                        lastActive: new Date(Date.now() - 86400000).toISOString(), // 1 day ago
                        current: false
                    },
                    {
                        id: 'session-2',
                        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                        location: 'London, UK',
                        lastActive: new Date(Date.now() - 604800000).toISOString(), // 1 week ago
                        current: false
                    }
                ];
            } catch (error) {
                console.error('Error loading sessions:', error);
            }
        },
        
        async saveAccountSettings() {
            this.clearMessages();
            this.isUpdating = true;
            
            try {
                // In a production app, send to server
                // For now, save to localStorage
                localStorage.setItem('accountSettings', JSON.stringify(this.accountSettings));
                
                // Update local user info
                this.userName = this.accountSettings.username;
                
                // Update initials
                this.userInitials = this.userName
                    .split(' ')
                    .map(word => word[0])
                    .join('')
                    .toUpperCase()
                    .substring(0, 2);
                
                this.successMessage = 'Account settings saved successfully';
                
                // Hide success message after a delay
                setTimeout(() => {
                    this.successMessage = null;
                }, 3000);
            } catch (error) {
                console.error('Error saving account settings:', error);
                this.errorMessage = 'Failed to save account settings';
            } finally {
                this.isUpdating = false;
            }
        },
        
        checkPasswordStrength() {
            // Calculate password strength
            let score = 0;
            
            // Length check
            if (this.securitySettings.newPassword.length >= 8) score++;
            if (this.securitySettings.newPassword.length >= 12) score++;
            
            // Complexity checks
            if (/[A-Z]/.test(this.securitySettings.newPassword)) score++;
            if (/[0-9]/.test(this.securitySettings.newPassword)) score++;
            if (/[^A-Za-z0-9]/.test(this.securitySettings.newPassword)) score++;
            
            this.passwordScore = score;
            
            // Categorize strength
            if (score <= 2) {
                this.passwordStrength = 'weak';
            } else if (score <= 3) {
                this.passwordStrength = 'medium';
            } else {
                this.passwordStrength = 'strong';
            }
        },
        
        get isPasswordFormValid() {
            return (
                this.securitySettings.currentPassword.length > 0 &&
                this.securitySettings.newPassword.length >= 8 &&
                this.securitySettings.newPassword === this.securitySettings.confirmPassword &&
                this.passwordScore >= 3 // At least medium strength
            );
        },
        
        async changePassword() {
            if (!this.isPasswordFormValid) return;
            
            this.clearMessages();
            this.isUpdating = true;
            
            try {
                const response = await fetch('/auth/change-password', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        current_password: this.securitySettings.currentPassword,
                        new_password: this.securitySettings.newPassword
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    this.successMessage = 'Password changed successfully';
                    
                    // Reset form
                    this.securitySettings.currentPassword = '';
                    this.securitySettings.newPassword = '';
                    this.securitySettings.confirmPassword = '';
                    this.passwordScore = 0;
                    this.passwordStrength = '';
                    
                    // Hide success message after a delay
                    setTimeout(() => {
                        this.successMessage = null;
                    }, 3000);
                } else {
                    this.errorMessage = data.error || 'Failed to change password';
                }
            } catch (error) {
                console.error('Error changing password:', error);
                this.errorMessage = 'Failed to change password';
            } finally {
                this.isUpdating = false;
            }
        },
        
        async revokeSession(sessionId) {
            if (sessionId === 'current-session') return; // Prevent revoking current session
            
            try {
                // In a production app, call API to revoke session
                // For now, just remove from local array
                this.sessions = this.sessions.filter(session => session.id !== sessionId);
                this.dispatchNotification('Session revoked successfully', 'success');
            } catch (error) {
                console.error('Error revoking session:', error);
                this.dispatchNotification('Failed to revoke session', 'error');
            }
        },
        
        async revokeAllSessions() {
            this.showConfirmModal(
                'Sign Out All Devices',
                'Are you sure you want to sign out from all other devices? This will end all active sessions except your current one.',
                'revoke-all-sessions',
                'Sign Out All'
            );
        },
        
        async handleRevokeAllSessions() {
            try {
                // In a production app, call API to revoke all sessions except current
                // For now, just keep the current session in local array
                this.sessions = this.sessions.filter(session => session.current);
                this.dispatchNotification('Signed out from all other devices', 'success');
            } catch (error) {
                console.error('Error revoking all sessions:', error);
                this.dispatchNotification('Failed to sign out from other devices', 'error');
            }
        },
        
        async saveNotificationSettings() {
            this.clearMessages();
            this.isUpdating = true;
            
            try {
                // In a production app, send to server
                // For now, save to localStorage
                localStorage.setItem('notificationSettings', JSON.stringify(this.notificationSettings));
                
                this.successMessage = 'Notification preferences saved successfully';
                
                // Hide success message after a delay
                setTimeout(() => {
                    this.successMessage = null;
                }, 3000);
            } catch (error) {
                console.error('Error saving notification settings:', error);
                this.errorMessage = 'Failed to save notification preferences';
            } finally {
                this.isUpdating = false;
            }
        },
        
        async requestBrowserPermission() {
            if (!this.notificationSettings.browserEnabled) return;
            
            try {
                // Request browser notification permission
                if (!("Notification" in window)) {
                    this.dispatchNotification('This browser does not support desktop notifications', 'warning');
                    this.notificationSettings.browserEnabled = false;
                    return;
                }
                
                if (Notification.permission === 'granted') {
                    return; // Already granted
                } else if (Notification.permission !== 'denied') {
                    const permission = await Notification.requestPermission();
                    
                    if (permission !== 'granted') {
                        this.dispatchNotification('Notification permission was not granted', 'warning');
                        this.notificationSettings.browserEnabled = false;
                    }
                } else {
                    this.dispatchNotification('Notification permission was previously denied', 'warning');
                    this.notificationSettings.browserEnabled = false;
                }
            } catch (error) {
                console.error('Error requesting notification permission:', error);
                this.notificationSettings.browserEnabled = false;
            }
        },
        
        async saveAppearanceSettings() {
            this.clearMessages();
            this.isUpdating = true;
            
            try {
                // Apply the theme and text size
                this.applyTheme(this.appearanceSettings.theme);
                this.applyTextSize(this.appearanceSettings.textSize);
                
                // In a production app, send to server
                // For now, save to localStorage
                localStorage.setItem('appearanceSettings', JSON.stringify(this.appearanceSettings));
                
                this.successMessage = 'Appearance settings saved successfully';
                
                // Hide success message after a delay
                setTimeout(() => {
                    this.successMessage = null;
                }, 3000);
            } catch (error) {
                console.error('Error saving appearance settings:', error);
                this.errorMessage = 'Failed to save appearance settings';
            } finally {
                this.isUpdating = false;
            }
        },
        
        applyTheme(theme) {
            // Apply theme to the document
            const root = document.documentElement;
            
            // First, remove any existing theme classes
            root.classList.remove('theme-light', 'theme-dark');
            
            if (theme === 'system') {
                // Use system preference
                const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                root.classList.add(prefersDark ? 'theme-dark' : 'theme-light');
            } else {
                // Use specific theme
                root.classList.add(`theme-${theme}`);
            }
            
            // Store the current theme for other pages to use
            localStorage.setItem('currentTheme', theme);
        },
        
        applyTextSize(size) {
            // Apply text size to the document
            document.documentElement.style.fontSize = `${size}%`;
            
            // Store the current text size for other pages to use
            localStorage.setItem('currentTextSize', size);
        },
        
        async saveDataSettings() {
            this.clearMessages();
            this.isUpdating = true;
            
            try {
                // In a production app, send to server
                // For now, save to localStorage
                localStorage.setItem('dataSettings', JSON.stringify(this.dataSettings));
                
                this.successMessage = 'Data & privacy settings saved successfully';
                
                // Hide success message after a delay
                setTimeout(() => {
                    this.successMessage = null;
                }, 3000);
            } catch (error) {
                console.error('Error saving data settings:', error);
                this.errorMessage = 'Failed to save data & privacy settings';
            } finally {
                this.isUpdating = false;
            }
        },
        
        async requestDataExport() {
            this.isExporting = true;
            
            try {
                // In a production app, call API to generate export
                // For now, simulate a delay
                await new Promise(resolve => setTimeout(resolve, 2000));
                
                // Create a fake export file
                const exportData = {
                    user: {
                        username: this.userName,
                        email: this.userEmail
                    },
                    conversations: [],
                    documents: [],
                    settings: {
                        account: this.accountSettings,
                        notifications: this.notificationSettings,
                        appearance: this.appearanceSettings,
                        data: this.dataSettings
                    },
                    exportDate: new Date().toISOString()
                };
                
                // Create a download link
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
                const downloadAnchorNode = document.createElement('a');
                downloadAnchorNode.setAttribute("href", dataStr);
                downloadAnchorNode.setAttribute("download", "triton_data_export.json");
                document.body.appendChild(downloadAnchorNode);
                downloadAnchorNode.click();
                downloadAnchorNode.remove();
                
                this.dispatchNotification('Data export complete', 'success');
            } catch (error) {
                console.error('Error exporting data:', error);
                this.dispatchNotification('Failed to export data', 'error');
            } finally {
                this.isExporting = false;
            }
        },
        
        confirmClearConversations() {
            this.showConfirmModal(
                'Clear Conversations',
                'Are you sure you want to clear all your conversations? This action cannot be undone.',
                'clear-conversations',
                'Clear All'
            );
        },
        
        confirmClearDocuments() {
            this.showConfirmModal(
                'Clear Documents',
                'Are you sure you want to delete all your uploaded documents? This action cannot be undone.',
                'clear-documents',
                'Delete All'
            );
        },
        
        confirmDeleteAccount() {
            this.showConfirmModal(
                'Delete Account',
                'Are you sure you want to permanently delete your account and all associated data? This action cannot be undone.',
                'delete-account',
                'Delete Account'
            );
        },
        
        showConfirmModal(title, message, type, confirmText) {
            this.confirmModal = {
                show: true,
                title,
                message,
                type,
                confirmText,
                input: '',
                callback: () => this.handleConfirmAction()
            };
        },
        
        async handleConfirmAction() {
            try {
                switch (this.confirmModal.type) {
                    case 'clear-conversations':
                        // In a production app, call API to clear conversations
                        this.dispatchNotification('All conversations cleared successfully', 'success');
                        break;
                        
                    case 'clear-documents':
                        // In a production app, call API to clear documents
                        this.dispatchNotification('All documents deleted successfully', 'success');
                        break;
                        
                    case 'delete-account':
                        if (this.confirmModal.input === 'DELETE') {
                            // In a production app, call API to delete account
                            this.dispatchNotification('Account deletion initiated. You will be signed out.', 'success');
                            
                            // Simulate logout after a delay
                            setTimeout(() => {
                                localStorage.removeItem('auth_token');
                                window.location.href = '/login';
                            }, 2000);
                        }
                        break;
                        
                    case 'revoke-all-sessions':
                        await this.handleRevokeAllSessions();
                        break;
                }
                
                // Close modal after action
                this.confirmModal.show = false;
            } catch (error) {
                console.error('Error handling confirmation action:', error);
                this.dispatchNotification('An error occurred', 'error');
            }
        },
        
        getDeviceIcon(userAgent) {
            if (/iPhone|iPad|iPod/i.test(userAgent)) return 'fa-apple';
            if (/Android/i.test(userAgent)) return 'fa-android';
            if (/Windows/i.test(userAgent)) return 'fa-windows';
            if (/Macintosh/i.test(userAgent)) return 'fa-apple';
            if (/Linux/i.test(userAgent)) return 'fa-linux';
            return 'fa-globe';
        },
        
        getDeviceName(userAgent) {
            if (/iPhone/i.test(userAgent)) return 'iPhone';
            if (/iPad/i.test(userAgent)) return 'iPad';
            if (/Android/i.test(userAgent)) {
                return /Tablet/i.test(userAgent) ? 'Android Tablet' : 'Android Phone';
            }
            if (/Windows/i.test(userAgent)) return 'Windows Device';
            if (/Macintosh/i.test(userAgent)) return 'Mac';
            if (/Linux/i.test(userAgent)) return 'Linux Device';
            return 'Unknown Device';
        },
        
        getBrowserName(userAgent) {
            if (/Chrome/i.test(userAgent) && !/Chromium|Edge|OPR|Brave/i.test(userAgent)) return 'Chrome';
            if (/Firefox/i.test(userAgent)) return 'Firefox';
            if (/Safari/i.test(userAgent) && !/Chrome|Chromium|Edge|OPR|Brave/i.test(userAgent)) return 'Safari';
            if (/Edge/i.test(userAgent)) return 'Edge';
            if (/OPR/i.test(userAgent)) return 'Opera';
            if (/Brave/i.test(userAgent)) return 'Brave';
            return 'Unknown Browser';
        },
        
        formatDate(dateString) {
            return DateFormatter.formatRelativeTime(dateString);
        },
        
        clearMessages() {
            this.errorMessage = null;
            this.successMessage = null;
        },
        
        dispatchNotification(message, type = 'info') {
            window.dispatchEvent(
                new CustomEvent('notification', {
                    detail: {
                        message,
                        type,
                        id: Date.now()
                    }
                })
            );
        }
    };
}
