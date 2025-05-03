/**
 * Admin Panel Application
 * Enterprise-grade admin functionality for Triton AI
 */

document.addEventListener('alpine:init', () => {
    Alpine.data('adminPanel', adminPanel);
});

function adminPanel() {
    return {
        // Authentication state
        isAuthenticated: false,
        isCheckingAuth: true,
        userInitials: '',
        userName: '',
        userEmail: '',
        userRole: '',
        
        // UI state
        activeTab: 'overview',
        isLoading: false,
        
        // Modals
        showEditUserModal: false,
        confirmModal: {
            show: false,
            title: '',
            message: '',
            action: null,
            confirmText: 'Confirm',
            data: null
        },
        
        // Overview stats
        stats: {
            totalUsers: 0,
            activeUsers: 0,
            totalConversations: 0,
            totalMessages: 0,
            documentsUploaded: 0
        },
        isLoadingStats: false,
        
        // Users management
        users: [],
        isLoadingUsers: false,
        selectedUser: null,
        userForm: {
            username: '',
            email: '',
            role: 'user',
            active: true
        },
        userError: null,
        userSuccess: null,
        
        // Invitations management
        invitations: [],
        isLoadingInvitations: false,
        inviteEmail: '',
        isInviting: false,
        
        // Documents management
        documents: [],
        isLoadingDocuments: false,
        
        // Logs management
        logs: [],
        isLoadingLogs: false,
        logLevel: 'all',
        
        // Config management
        config: {},
        isLoadingConfig: false,
        configForm: {},
        configError: null,
        configSuccess: null,
        
        /**
         * Initialize the admin panel
         */
        async initialize() {
            try {
                // Check authentication
                const user = await this.checkAuth();
                
                if (!user) {
                    this.isAuthenticated = false;
                    this.isCheckingAuth = false;
                    return;
                }
                
                if (user.role !== 'admin') {
                    this.isAuthenticated = false;
                    this.isCheckingAuth = false;
                    
                    // Display error message for non-admin users
                    this.dispatchNotification('Admin access required', 'error');
                    
                    // Redirect to home page after delay
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 2000);
                    
                    return;
                }
                
                // Set user info
                this.userInitials = this.getInitials(user.username);
                this.userName = user.username;
                this.userEmail = user.email;
                this.userRole = user.role;
                
                this.isAuthenticated = true;
                this.isCheckingAuth = false;
                
                // Load initial data
                this.loadOverviewStats();
                
                // Set up charts after DOM is ready
                this.$nextTick(() => {
                    this.setupCharts();
                });
            } catch (error) {
                console.error('Initialization error:', error);
                this.isAuthenticated = false;
                this.isCheckingAuth = false;
                this.dispatchNotification('Failed to initialize admin panel', 'error');
            }
        },
        
        /**
         * Check if user is authenticated
         */
        async checkAuth() {
            try {
                const response = await fetch('/auth/me', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    return data.user;
                }
                
                return null;
            } catch (error) {
                console.error('Auth check error:', error);
                return null;
            }
        },
        
        /**
         * Get user initials for avatar
         */
        getInitials(name) {
            if (!name) return '';
            
            return name
                .split(' ')
                .map(part => part.charAt(0).toUpperCase())
                .slice(0, 2)
                .join('');
        },
        
        /**
         * Load overview stats and chart data
         */
        async loadOverviewStats() {
            this.isLoadingStats = true;
            
            try {
                const response = await fetch('/admin/stats', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Update stats
                    this.stats = data.stats;
                    
                    // Update charts
                    this.$nextTick(() => {
                        this.updateUserActivityChart(data.userActivity);
                        this.updateModelUsageChart(data.modelUsage);
                    });
                } else {
                    this.dispatchNotification('Failed to load overview stats', 'error');
                }
            } catch (error) {
                console.error('Load stats error:', error);
                this.dispatchNotification('Failed to load overview stats', 'error');
            } finally {
                this.isLoadingStats = false;
            }
        },
        
        /**
         * Set up charts
         */
        setupCharts() {
            // User Activity Chart
            const userActivityCtx = document.getElementById('userActivityChart');
            if (userActivityCtx) {
                this.userActivityChart = new Chart(userActivityCtx, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Active Users',
                            data: [],
                            borderColor: '#0ea5e9',
                            backgroundColor: 'rgba(14, 165, 233, 0.1)',
                            tension: 0.3,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    precision: 0
                                }
                            }
                        }
                    }
                });
            }
            
            // Model Usage Chart
            const modelUsageCtx = document.getElementById('modelUsageChart');
            if (modelUsageCtx) {
                this.modelUsageChart = new Chart(modelUsageCtx, {
                    type: 'doughnut',
                    data: {
                        labels: [],
                        datasets: [{
                            data: [],
                            backgroundColor: [
                                '#0ea5e9',
                                '#3f5f87',
                                '#22c55e',
                                '#f59e0b',
                                '#ef4444'
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'right'
                            }
                        }
                    }
                });
            }
        },
        
        /**
         * Update user activity chart with new data
         */
        updateUserActivityChart(data) {
            if (!this.userActivityChart) return;
            
            // Process data for chart
            const dates = data.map(item => {
                const date = new Date(item.date);
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            });
            
            const counts = data.map(item => item.count);
            
            // Update chart
            this.userActivityChart.data.labels = dates;
            this.userActivityChart.data.datasets[0].data = counts;
            this.userActivityChart.update();
        },
        
        /**
         * Update model usage chart with new data
         */
        updateModelUsageChart(data) {
            if (!this.modelUsageChart) return;
            
            // Process data for chart
            const labels = data.map(item => item.model);
            const counts = data.map(item => item.count);
            
            // Update chart
            this.modelUsageChart.data.labels = labels;
            this.modelUsageChart.data.datasets[0].data = counts;
            this.modelUsageChart.update();
        },
        
        /**
         * Load users list
         */
        async loadUsers() {
            this.isLoadingUsers = true;
            this.users = [];
            
            try {
                const response = await fetch('/admin/users', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.users = data.users;
                } else {
                    this.dispatchNotification('Failed to load users', 'error');
                }
            } catch (error) {
                console.error('Load users error:', error);
                this.dispatchNotification('Failed to load users', 'error');
            } finally {
                this.isLoadingUsers = false;
            }
        },
        
        /**
         * Open user edit modal
         */
        openEditUserModal(user = null) {
            this.selectedUser = user;
            this.userError = null;
            this.userSuccess = null;
            
            if (user) {
                // Edit existing user
                this.userForm = {
                    username: user.username,
                    role: user.role,
                    active: user.active
                };
            } else {
                // New invitation
                this.userForm = {
                    email: '',
                    role: 'user'
                };
            }
            
            this.showEditUserModal = true;
        },
        
        /**
         * Save user or send invitation
         */
        async saveUser() {
            this.userError = null;
            this.userSuccess = null;
            
            if (this.selectedUser) {
                // Update existing user
                try {
                    const response = await fetch(`/admin/users/${this.selectedUser.user_id}`, {
                        method: 'PUT',
                        credentials: 'include',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            username: this.userForm.username,
                            role: this.userForm.role,
                            active: this.userForm.active
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        this.userSuccess = 'User updated successfully';
                        
                        // Reload users list
                        await this.loadUsers();
                        
                        // Close modal after delay
                        setTimeout(() => {
                            this.showEditUserModal = false;
                        }, 1500);
                    } else {
                        this.userError = data.error || 'Failed to update user';
                    }
                } catch (error) {
                    console.error('Update user error:', error);
                    this.userError = 'Failed to update user';
                }
            } else {
                // Send invitation
                try {
                    const response = await fetch('/auth/invite', {
                        method: 'POST',
                        credentials: 'include',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            email: this.userForm.email
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        this.userSuccess = `Invitation sent successfully to ${this.userForm.email}`;
                        
                        // Reload invitations list
                        await this.loadInvitations();
                        
                        // Close modal after delay
                        setTimeout(() => {
                            this.showEditUserModal = false;
                        }, 1500);
                    } else {
                        this.userError = data.error || 'Failed to send invitation';
                    }
                } catch (error) {
                    console.error('Send invitation error:', error);
                    this.userError = 'Failed to send invitation';
                }
            }
        },
        
        /**
         * Load invitations list
         */
        async loadInvitations() {
            this.isLoadingInvitations = true;
            this.invitations = [];
            
            try {
                const response = await fetch('/admin/invitations', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.invitations = data.invitations;
                } else {
                    this.dispatchNotification('Failed to load invitations', 'error');
                }
            } catch (error) {
                console.error('Load invitations error:', error);
                this.dispatchNotification('Failed to load invitations', 'error');
            } finally {
                this.isLoadingInvitations = false;
            }
        },
        
        /**
         * Send a new invitation
         */
        async sendInvitation() {
            if (!this.inviteEmail || this.isInviting) return;
            
            this.isInviting = true;
            
            try {
                const response = await fetch('/auth/invite', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email: this.inviteEmail
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    this.dispatchNotification(`Invitation sent successfully to ${this.inviteEmail}`, 'success');
                    
                    // Clear form
                    this.inviteEmail = '';
                    
                    // Reload invitations
                    await this.loadInvitations();
                } else {
                    this.dispatchNotification(data.error || 'Failed to send invitation', 'error');
                }
            } catch (error) {
                console.error('Send invitation error:', error);
                this.dispatchNotification('Failed to send invitation', 'error');
            } finally {
                this.isInviting = false;
            }
        },
        
        /**
         * Delete invitation confirmation
         */
        confirmDeleteInvitation(invitation) {
            this.confirmAction(
                () => this.deleteInvitation(invitation.invitation_id),
                'Delete Invitation',
                `Are you sure you want to delete the invitation for ${invitation.email}?`,
                'Delete'
            );
        },
        
        /**
         * Delete invitation
         */
        async deleteInvitation(invitation_id) {
            try {
                const response = await fetch(`/admin/invitations/${invitation_id}`, {
                    method: 'DELETE',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    this.dispatchNotification('Invitation deleted successfully', 'success');
                    await this.loadInvitations();
                } else {
                    const data = await response.json();
                    this.dispatchNotification(data.error || 'Failed to delete invitation', 'error');
                }
            } catch (error) {
                console.error('Delete invitation error:', error);
                this.dispatchNotification('Failed to delete invitation', 'error');
            }
        },
        
        /**
         * Load documents list
         */
        async loadDocuments() {
            this.isLoadingDocuments = true;
            this.documents = [];
            
            try {
                const response = await fetch('/admin/documents', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.documents = data.documents;
                } else {
                    this.dispatchNotification('Failed to load documents', 'error');
                }
            } catch (error) {
                console.error('Load documents error:', error);
                this.dispatchNotification('Failed to load documents', 'error');
            } finally {
                this.isLoadingDocuments = false;
            }
        },
        
        /**
         * Delete document confirmation
         */
        confirmDeleteDocument(document) {
            this.confirmAction(
                () => this.deleteDocument(document.doc_id),
                'Delete Document',
                `Are you sure you want to delete the document "${document.name}"?`,
                'Delete'
            );
        },
        
        /**
         * Delete document
         */
        async deleteDocument(doc_id) {
            try {
                const response = await fetch(`/admin/documents/${doc_id}`, {
                    method: 'DELETE',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    this.dispatchNotification('Document deleted successfully', 'success');
                    await this.loadDocuments();
                } else {
                    const data = await response.json();
                    this.dispatchNotification(data.error || 'Failed to delete document', 'error');
                }
            } catch (error) {
                console.error('Delete document error:', error);
                this.dispatchNotification('Failed to delete document', 'error');
            }
        },
        
        /**
         * Format file size for display
         */
        formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },
        
        /**
         * Load system logs
         */
        async loadLogs() {
            this.isLoadingLogs = true;
            this.logs = [];
            
            try {
                const response = await fetch(`/admin/logs?level=${this.logLevel}`, {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.logs = data.logs;
                } else {
                    this.dispatchNotification('Failed to load logs', 'error');
                }
            } catch (error) {
                console.error('Load logs error:', error);
                this.dispatchNotification('Failed to load logs', 'error');
            } finally {
                this.isLoadingLogs = false;
            }
        },
        
        /**
         * Clear logs confirmation
         */
        confirmClearLogs() {
            this.confirmAction(
                () => this.clearLogs(),
                'Clear Logs',
                'Are you sure you want to clear all system logs? This action cannot be undone.',
                'Clear'
            );
        },
        
        /**
         * Clear system logs
         */
        async clearLogs() {
            try {
                const response = await fetch('/admin/logs/clear', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    this.dispatchNotification('Logs cleared successfully', 'success');
                    await this.loadLogs();
                } else {
                    const data = await response.json();
                    this.dispatchNotification(data.error || 'Failed to clear logs', 'error');
                }
            } catch (error) {
                console.error('Clear logs error:', error);
                this.dispatchNotification('Failed to clear logs', 'error');
            }
        },
        
        /**
         * Load system configuration
         */
        async loadSystemConfig() {
            this.isLoadingConfig = true;
            this.configError = null;
            this.configSuccess = null;
            
            try {
                const response = await fetch('/admin/config', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.config = data.config;
                    
                    // Initialize config form
                    this.configForm = {};
                    this.config.forEach(item => {
                        this.configForm[item.key] = item.value;
                    });
                } else {
                    this.configError = 'Failed to load system configuration';
                }
            } catch (error) {
                console.error('Load config error:', error);
                this.configError = 'Failed to load system configuration';
            } finally {
                this.isLoadingConfig = false;
            }
        },
        
        /**
         * Save system configuration
         */
        async saveSystemConfig() {
            this.configError = null;
            this.configSuccess = null;
            
            try {
                const response = await fetch('/admin/config', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(this.configForm)
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    this.configSuccess = 'Configuration saved successfully';
                    
                    // Reload config
                    await this.loadSystemConfig();
                } else {
                    this.configError = data.error || 'Failed to save configuration';
                }
            } catch (error) {
                console.error('Save config error:', error);
                this.configError = 'Failed to save configuration';
            }
        },
        
        /**
         * Format date for display
         */
        formatDate(dateString) {
            if (!dateString) return 'N/A';
            
            const date = new Date(dateString);
            
            if (isNaN(date.getTime())) {
                return 'Invalid date';
            }
            
            return date.toLocaleString();
        },
        
        /**
         * Format log level for display with appropriate styling
         */
        getLogLevelClass(level) {
            switch (level.toUpperCase()) {
                case 'ERROR':
                    return 'bg-danger-100 text-danger-700';
                case 'WARNING':
                    return 'bg-warning-100 text-warning-700';
                case 'INFO':
                    return 'bg-primary-100 text-primary-700';
                case 'DEBUG':
                    return 'bg-secondary-100 text-secondary-700';
                default:
                    return 'bg-secondary-100 text-secondary-700';
            }
        },
        
        /**
         * Set up confirmation modal
         */
        confirmAction(action, title, message, confirmText = 'Confirm') {
            this.confirmModal = {
                show: true,
                title: title,
                message: message,
                action: action,
                confirmText: confirmText
            };
        },
        
        /**
         * Execute confirmed action
         */
        executeConfirmedAction() {
            if (this.confirmModal.action) {
                this.confirmModal.action();
            }
            
            this.confirmModal.show = false;
        },
        
        /**
         * Display a notification
         */
        dispatchNotification(message, type = 'info') {
            const id = Date.now();
            const event = new CustomEvent('notification', {
                detail: {
                    message,
                    type,
                    id
                }
            });
            
            window.dispatchEvent(event);
        }
    };
}
