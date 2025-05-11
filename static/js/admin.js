/**
 * Admin Panel Application
 * Provides administrative functionality for Triton AI
 */

document.addEventListener('alpine:init', () => {
    Alpine.data('adminPanel', adminPanel);
});

function adminPanel() {
    return {
        // Authentication and state
        isAuthenticated: false,
        isCheckingAuth: true,
        userInitials: '',
        userName: '',
        userEmail: '',
        userRole: '',
        
        // Active tab
        activeTab: 'overview',
        
        // Data
        stats: {
            totalUsers: 0,
            activeUsers: 0,
            totalConversations: 0,
            totalMessages: 0,
            documentsUploaded: 0
        },
        users: [],
        invitations: [],
        documents: [],
        logs: [],
        
        // Charts
        userActivityChart: null,
        modelUsageChart: null,
        
        // Loading states
        isLoadingUsers: false,
        isLoadingInvitations: false,
        isLoadingDocuments: false,
        isLoadingLogs: false,
        isLoadingConfig: false,
        
        // Form data
        inviteEmail: '',
        userForm: {
            email: '',
            username: '',
            role: 'user',
            active: true
        },
        selectedUser: null,
        logFilter: {
            level: 'all',
            limit: 100
        },
        
        // Modals
        showEditUserModal: false,
        confirmModal: {
            show: false,
            title: '',
            message: '',
            confirmText: 'Confirm',
            action: null,
            params: null
        },
        
        // Error and success messages
        userError: null,
        userSuccess: null,
        configError: null,
        configSuccess: null,
        
        /**
         * Initialize the application
         */
        async initialize() {
            try {
                // Check authentication
                const response = await fetch('/auth/me');
                
                if (response.ok) {
                    const data = await response.json();
                    
                    if (data.user) {
                        this.isAuthenticated = true;
                        this.userName = data.user.username;
                        this.userEmail = data.user.email;
                        this.userRole = data.user.role;
                        this.userInitials = this.getInitials(data.user.username);
                        
                        // Check if user is admin
                        if (data.user.role !== 'admin') {
                            this.isAuthenticated = false;
                            return;
                        }
                        
                        // Load initial data
                        this.loadOverviewStats();
                    } else {
                        this.isAuthenticated = false;
                    }
                } else {
                    this.isAuthenticated = false;
                }
            } catch (error) {
                console.error('Authentication error:', error);
                this.isAuthenticated = false;
            } finally {
                this.isCheckingAuth = false;
            }
        },
        
        /**
         * Get user initials for avatar display
         */
        getInitials(name) {
            if (!name) return '';
            
            const parts = name.split(' ');
            if (parts.length === 1) {
                return parts[0].charAt(0).toUpperCase();
            }
            
            return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase();
        },
        
        /**
         * Load overview statistics
         */
        async loadOverviewStats() {
            try {
                const response = await fetch('/admin/stats');
                
                if (response.ok) {
                    const data = await response.json();
                    this.stats = data.stats;
                    
                    // Initialize charts with the data
                    this.initUserActivityChart(data.userActivity);
                    this.initModelUsageChart(data.modelUsage);
                } else {
                    const errorData = await response.json();
                    this.dispatchNotification(errorData.error || 'Failed to load stats', 'error');
                }
            } catch (error) {
                console.error('Error loading stats:', error);
                this.dispatchNotification('Failed to load dashboard stats', 'error');
            }
        },
        
        /**
         * Initialize user activity chart
         */
        initUserActivityChart(activityData) {
            // If the chart element doesn't exist, return early to prevent errors
            const chartElement = document.getElementById('userActivityChart');
            if (!chartElement) {
                console.warn('User activity chart element not found');
                return;
            }

            // Ensure we have data
            if (!activityData || !Array.isArray(activityData) || activityData.length === 0) {
                console.warn('No user activity data available');
                return;
            }
            
            // Sort data by date
            activityData.sort((a, b) => new Date(a.date) - new Date(b.date));
            
            // Create a deep copy of the data to avoid circular references
            const labels = [...activityData.map(item => {
                const date = new Date(item.date);
                return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
            })];
            
            const values = [...activityData.map(item => item.count)];
            
            // Destroy existing chart if it exists
            if (this.userActivityChart) {
                this.userActivityChart.destroy();
            }
            
            try {
                // Create new chart with immutable data objects
                const chartConfig = {
                    type: 'line',
                    data: {
                        labels,
                        datasets: [{
                            label: 'Active Users',
                            data: values,
                            backgroundColor: 'rgba(14, 165, 233, 0.2)',
                            borderColor: 'rgba(14, 165, 233, 1)',
                            borderWidth: 2,
                            pointBackgroundColor: 'rgba(14, 165, 233, 1)',
                            pointRadius: 4,
                            tension: 0.2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    precision: 0
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                display: false
                            },
                            tooltip: {
                                mode: 'index',
                                intersect: false
                            }
                        }
                    }
                };
                
                this.userActivityChart = new Chart(chartElement, chartConfig);
            } catch (error) {
                console.error('Error creating user activity chart:', error);
            }
        },
        
        /**
         * Initialize model usage chart
         */
        initModelUsageChart(modelData) {
            // If the chart element doesn't exist, return early to prevent errors
            const chartElement = document.getElementById('modelUsageChart');
            if (!chartElement) {
                console.warn('Model usage chart element not found');
                return;
            }
            
            // Ensure we have data
            if (!modelData || !Array.isArray(modelData) || modelData.length === 0) {
                console.warn('No model usage data available');
                return;
            }
            
            // Create deep copies of arrays to prevent circular references
            const labels = [...modelData.map(item => item.model)];
            const values = [...modelData.map(item => item.count)];
            
            // Generate colors for each model
            const backgroundColors = [
                'rgba(14, 165, 233, 0.7)',
                'rgba(248, 113, 113, 0.7)',
                'rgba(16, 185, 129, 0.7)',
                'rgba(251, 191, 36, 0.7)',
                'rgba(139, 92, 246, 0.7)'
            ];
            
            // Destroy existing chart if it exists
            if (this.modelUsageChart) {
                this.modelUsageChart.destroy();
            }
            
            try {
                // Create new chart with immutable configuration objects
                const chartConfig = {
                    type: 'doughnut',
                    data: {
                        labels,
                        datasets: [{
                            data: values,
                            backgroundColor: backgroundColors.slice(0, values.length),
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'right',
                                labels: {
                                    boxWidth: 15,
                                    padding: 15
                                }
                            },
                            tooltip: {
                                callbacks: {
                                    label: function(context) {
                                        const label = context.label || '';
                                        const value = context.raw || 0;
                                        const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                        const percentage = Math.round((value / total) * 100);
                                        return `${label}: ${value} (${percentage}%)`;
                                    }
                                }
                            }
                        }
                    }
                };
                
                this.modelUsageChart = new Chart(chartElement, chartConfig);
            } catch (error) {
                console.error('Error creating model usage chart:', error);
            }
        },
        
        /**
         * Load user data
         */
        async loadUsers() {
            this.isLoadingUsers = true;
            
            try {
                const response = await fetch('/admin/users');
                
                if (response.ok) {
                    const data = await response.json();
                    this.users = data.users;
                } else {
                    const errorData = await response.json();
                    this.dispatchNotification(errorData.error || 'Failed to load users', 'error');
                }
            } catch (error) {
                console.error('Error loading users:', error);
                this.dispatchNotification('Failed to load user data', 'error');
            } finally {
                this.isLoadingUsers = false;
            }
        },
        
        /**
         * Load invitations
         */
        async loadInvitations() {
            this.isLoadingInvitations = true;
            
            try {
                const response = await fetch('/admin/invitations');
                
                if (response.ok) {
                    const data = await response.json();
                    this.invitations = data.invitations;
                } else {
                    const errorData = await response.json();
                    this.dispatchNotification(errorData.error || 'Failed to load invitations', 'error');
                }
            } catch (error) {
                console.error('Error loading invitations:', error);
                this.dispatchNotification('Failed to load invitation data', 'error');
            } finally {
                this.isLoadingInvitations = false;
            }
        },
        
        /**
         * Load documents
         */
        async loadDocuments() {
            this.isLoadingDocuments = true;
            
            try {
                const response = await fetch('/admin/documents');
                
                if (response.ok) {
                    const data = await response.json();
                    this.documents = data.documents;
                } else {
                    const errorData = await response.json();
                    this.dispatchNotification(errorData.error || 'Failed to load documents', 'error');
                }
            } catch (error) {
                console.error('Error loading documents:', error);
                this.dispatchNotification('Failed to load document data', 'error');
            } finally {
                this.isLoadingDocuments = false;
            }
        },
        
        /**
         * Load system logs
         */
        async loadLogs() {
            this.isLoadingLogs = true;
            
            try {
                const queryParams = new URLSearchParams();
                if (this.logFilter.level) queryParams.append('level', this.logFilter.level);
                if (this.logFilter.limit) queryParams.append('limit', this.logFilter.limit);
                
                const response = await fetch(`/admin/logs?${queryParams.toString()}`);
                
                if (response.ok) {
                    const data = await response.json();
                    this.logs = data.logs;
                } else {
                    const errorData = await response.json();
                    this.dispatchNotification(errorData.error || 'Failed to load logs', 'error');
                }
            } catch (error) {
                console.error('Error loading logs:', error);
                this.dispatchNotification('Failed to load system logs', 'error');
            } finally {
                this.isLoadingLogs = false;
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
                const response = await fetch('/admin/config');
                
                if (response.ok) {
                    const data = await response.json();
                    this.config = data.config;
                } else {
                    const errorData = await response.json();
                    this.configError = errorData.error || 'Failed to load system configuration';
                }
            } catch (error) {
                console.error('Error loading system config:', error);
                this.configError = 'Failed to load system configuration';
            } finally {
                this.isLoadingConfig = false;
            }
        },
        
        /**
         * Save system configuration
         */
        async saveSystemConfig(event) {
            event.preventDefault();
            this.isLoadingConfig = true;
            this.configError = null;
            this.configSuccess = null;
            
            try {
                // Extract form data
                const formData = new FormData(event.target);
                const configData = {};
                
                // Convert FormData to object
                for (const [key, value] of formData.entries()) {
                    configData[key] = value;
                }
                
                const response = await fetch('/admin/config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(configData)
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.configSuccess = data.message || 'Configuration saved successfully';
                    
                    // Reload the configuration
                    await this.loadSystemConfig();
                } else {
                    const errorData = await response.json();
                    this.configError = errorData.error || 'Failed to save configuration';
                }
            } catch (error) {
                console.error('Error saving config:', error);
                this.configError = 'Failed to save configuration';
            } finally {
                this.isLoadingConfig = false;
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
                // Create new user invitation
                this.userForm = {
                    email: '',
                    role: 'user',
                    active: true
                };
            }
            
            this.showEditUserModal = true;
        },
        
        /**
         * Save user changes or send invitation
         */
        async saveUser(event) {
            event.preventDefault();
            this.userError = null;
            this.userSuccess = null;
            
            try {
                if (this.selectedUser) {
                    // Update existing user
                    const response = await fetch(`/admin/users/${this.selectedUser.user_id}`, {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            username: this.userForm.username,
                            role: this.userForm.role,
                            active: this.userForm.active
                        })
                    });
                    
                    if (response.ok) {
                        const data = await response.json();
                        this.userSuccess = data.message || 'User updated successfully';
                        await this.loadUsers();
                    } else {
                        const errorData = await response.json();
                        this.userError = errorData.error || 'Failed to update user';
                    }
                } else {
                    // Send invitation to new user
                    const response = await fetch('/auth/invite', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            email: this.userForm.email
                        })
                    });
                    
                    if (response.ok) {
                        const data = await response.json();
                        this.userSuccess = data.message || 'Invitation sent successfully';
                        await this.loadInvitations();
                    } else {
                        const errorData = await response.json();
                        this.userError = errorData.error || 'Failed to send invitation';
                    }
                }
            } catch (error) {
                console.error('Error saving user:', error);
                this.userError = 'An error occurred while processing your request';
            }
        },
        
        /**
         * Show confirmation modal
         */
        showConfirmation(title, message, confirmText, action, params = null) {
            this.confirmModal = {
                show: true,
                title,
                message,
                confirmText,
                action,
                params
            };
        },
        
        /**
         * Execute confirmed action
         */
        executeConfirmedAction() {
            if (this.confirmModal.action) {
                this[this.confirmModal.action](this.confirmModal.params);
            }
            
            this.confirmModal.show = false;
        },
        
        /**
         * Delete invitation
         */
        confirmDeleteInvitation(invitation) {
            this.showConfirmation(
                'Delete Invitation',
                `Are you sure you want to delete the invitation for ${invitation.email}?`,
                'Delete',
                'deleteInvitation',
                invitation.invitation_id
            );
        },
        
        /**
         * Delete invitation
         */
        async deleteInvitation(invitationId) {
            try {
                const response = await fetch(`/admin/invitations/${invitationId}`, {
                    method: 'DELETE'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.dispatchNotification(data.message || 'Invitation deleted successfully', 'success');
                    await this.loadInvitations();
                } else {
                    const errorData = await response.json();
                    this.dispatchNotification(errorData.error || 'Failed to delete invitation', 'error');
                }
            } catch (error) {
                console.error('Error deleting invitation:', error);
                this.dispatchNotification('Failed to delete invitation', 'error');
            }
        },
        
        /**
         * Confirm document deletion
         */
        confirmDeleteDocument(document) {
            this.showConfirmation(
                'Delete Document',
                `Are you sure you want to delete the document "${document.name}"?`,
                'Delete',
                'deleteDocument',
                document.doc_id
            );
        },
        
        /**
         * Delete document
         */
        async deleteDocument(docId) {
            try {
                const response = await fetch(`/admin/documents/${docId}`, {
                    method: 'DELETE'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.dispatchNotification(data.message || 'Document deleted successfully', 'success');
                    await this.loadDocuments();
                } else {
                    const errorData = await response.json();
                    this.dispatchNotification(errorData.error || 'Failed to delete document', 'error');
                }
            } catch (error) {
                console.error('Error deleting document:', error);
                this.dispatchNotification('Failed to delete document', 'error');
            }
        },
        
        /**
         * Confirm log clear
         */
        confirmClearLogs() {
            this.showConfirmation(
                'Clear System Logs',
                'Are you sure you want to clear all system logs? This action cannot be undone.',
                'Clear Logs',
                'clearLogs'
            );
        },
        
        /**
         * Clear system logs
         */
        async clearLogs() {
            try {
                const response = await fetch('/admin/logs/clear', {
                    method: 'POST'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.dispatchNotification(data.message || 'Logs cleared successfully', 'success');
                    await this.loadLogs();
                } else {
                    const errorData = await response.json();
                    this.dispatchNotification(errorData.error || 'Failed to clear logs', 'error');
                }
            } catch (error) {
                console.error('Error clearing logs:', error);
                this.dispatchNotification('Failed to clear logs', 'error');
            }
        },
        
        /**
         * Format date for display using user's local timezone
         */
        formatDate(dateString) {
            return DateFormatter.formatDateTime(dateString, {
                monthFormat: 'short'
            });
        },
        
        /**
         * Get CSS classes for user status badge
         */
        getStatusClass(isActive) {
            return isActive 
                ? 'bg-success-100 text-success-700' 
                : 'bg-danger-100 text-danger-700';
        },
        
        /**
         * Get CSS classes for log level badge
         */
        getLogLevelClass(level) {
            const classes = {
                'ERROR': 'bg-danger-100 text-danger-700',
                'WARNING': 'bg-warning-100 text-warning-700',
                'INFO': 'bg-primary-100 text-primary-700',
                'DEBUG': 'bg-secondary-100 text-secondary-700'
            };
            return classes[level] || 'bg-secondary-100 text-secondary-700';
        },
        
        /**
         * Display a notification
         */
        dispatchNotification(message, type = 'info') {
            window.dispatchEvent(new CustomEvent('notification', {
                detail: {
                    message,
                    type,
                    id: Date.now()
                }
            }));
        }
    };
}
