/**
 * Admin Panel Application
 * Handles administrative functions for Triton AI
 */

document.addEventListener('alpine:init', () => {
    Alpine.data('adminPanel', adminPanel);
});

function adminPanel() {
    return {
        // Authentication and user state
        isAuthenticated: false,
        isCheckingAuth: true,
        userInitials: '',
        userName: '',
        userEmail: '',
        userRole: '',
        
        // Active tab
        activeTab: 'overview', // overview, users, invitations, documents, logs, config
        
        // Overview stats
        stats: {
            totalUsers: 0,
            activeUsers: 0,
            totalConversations: 0,
            totalMessages: 0,
            documentsUploaded: 0
        },
        
        // Users management
        users: [],
        isLoadingUsers: false,
        showEditUserModal: false,
        selectedUser: null,
        userForm: {
            username: '',
            email: '',
            role: 'user',
            active: true
        },
        userSuccess: null,
        userError: null,
        
        // Invitations management
        invitations: [],
        isLoadingInvitations: false,
        inviteEmail: '',
        isInviting: false,
        
        // Documents management
        documents: [],
        isLoadingDocuments: false,
        
        // System logs
        logs: [],
        isLoadingLogs: false,
        logLevel: 'all',
        
        // System configuration
        configForm: {
            azureEndpoint: '',
            azureApiKey: '',
            maxUploadSize: 50,
            defaultSearchEngine: 'google',
            logLevel: 'INFO'
        },
        isLoadingConfig: false,
        configSuccess: null,
        configError: null,
        
        // Confirmation modal
        confirmModal: {
            show: false,
            title: '',
            message: '',
            action: null,
            param: null,
            confirmText: 'Confirm'
        },
        
        /**
         * Initialize the admin panel
         */
        async initialize() {
            try {
                this.isCheckingAuth = true;
                
                // Check authentication status
                const response = await fetch('/auth/me', {
                    method: 'GET',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Check if user is admin
                    if (data.user.role !== 'admin') {
                        this.isAuthenticated = false;
                        return;
                    }
                    
                    this.isAuthenticated = true;
                    this.userName = data.user.username;
                    this.userEmail = data.user.email;
                    this.userRole = data.user.role;
                    this.userInitials = this.getInitials(data.user.username);
                    
                    // Load data for active tab
                    await this.loadTabData(this.activeTab);
                } else {
                    this.isAuthenticated = false;
                }
            } catch (error) {
                console.error('Initialization error:', error);
                this.isAuthenticated = false;
            } finally {
                this.isCheckingAuth = false;
            }
        },
        
        /**
         * Load data for the active tab
         */
        async loadTabData(tab) {
            this.activeTab = tab;
            
            switch (tab) {
                case 'overview':
                    await this.loadOverviewStats();
                    break;
                case 'users':
                    await this.loadUsers();
                    break;
                case 'invitations':
                    await this.loadInvitations();
                    break;
                case 'documents':
                    await this.loadDocuments();
                    break;
                case 'logs':
                    await this.loadLogs();
                    break;
                case 'config':
                    await this.loadSystemConfig();
                    break;
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
         * Load overview statistics
         */
        async loadOverviewStats() {
            try {
                const response = await fetch('/admin/stats', {
                    method: 'GET',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.stats = data.stats;
                    
                    // Initialize charts
                    this.$nextTick(() => {
                        this.initUserActivityChart(data.userActivity);
                        this.initModelUsageChart(data.modelUsage);
                    });
                } else {
                    // If API not implemented, use sample data for development
                    this.stats = {
                        totalUsers: 12,
                        activeUsers: 8,
                        totalConversations: 156,
                        totalMessages: 1236,
                        documentsUploaded: 24
                    };
                    
                    // Initialize charts with sample data
                    this.$nextTick(() => {
                        this.initUserActivityChart([
                            { date: '2023-09-01', count: 5 },
                            { date: '2023-09-02', count: 7 },
                            { date: '2023-09-03', count: 12 },
                            { date: '2023-09-04', count: 8 },
                            { date: '2023-09-05', count: 10 },
                            { date: '2023-09-06', count: 15 },
                            { date: '2023-09-07', count: 11 }
                        ]);
                        
                        this.initModelUsageChart([
                            { model: 'GPT-4o', count: 450 },
                            { model: 'GPT-4', count: 300 },
                            { model: 'GPT-3.5', count: 200 },
                            { model: 'Claude-3', count: 150 },
                            { model: 'Other', count: 100 }
                        ]);
                    });
                }
            } catch (error) {
                console.error('Stats loading error:', error);
                this.dispatchNotification('Failed to load statistics', 'error');
            }
        },
        
        /**
         * Initialize user activity chart
         */
        initUserActivityChart(data) {
            const ctx = document.getElementById('userActivityChart');
            if (!ctx) return;
            
            // Destroy existing chart if it exists
            if (this.userActivityChart) {
                this.userActivityChart.destroy();
            }
            
            const labels = data.map(item => {
                const date = new Date(item.date);
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            });
            
            const values = data.map(item => item.count);
            
            this.userActivityChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Active Users',
                        data: values,
                        borderColor: '#0ea5e9',
                        backgroundColor: 'rgba(14, 165, 233, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.3
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
        },
        
        /**
         * Initialize model usage chart
         */
        initModelUsageChart(data) {
            const ctx = document.getElementById('modelUsageChart');
            if (!ctx) return;
            
            // Destroy existing chart if it exists
            if (this.modelUsageChart) {
                this.modelUsageChart.destroy();
            }
            
            const labels = data.map(item => item.model);
            const values = data.map(item => item.count);
            
            this.modelUsageChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: values,
                        backgroundColor: [
                            '#0ea5e9',
                            '#3b82f6',
                            '#6366f1',
                            '#8b5cf6',
                            '#a855f7'
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
        },
        
        /**
         * Load users list
         */
        async loadUsers() {
            this.isLoadingUsers = true;
            
            try {
                const response = await fetch('/admin/users', {
                    method: 'GET',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.users = data.users || [];
                } else {
                    this.dispatchNotification('Failed to load users', 'error');
                }
            } catch (error) {
                console.error('Error loading users:', error);
                this.dispatchNotification('Failed to load users', 'error');
            } finally {
                this.isLoadingUsers = false;
            }
        },
        
        /**
         * Load invitations list
         */
        async loadInvitations() {
            this.isLoadingInvitations = true;
            
            try {
                const response = await fetch('/admin/invitations', {
                    method: 'GET',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.invitations = data.invitations || [];
                } else {
                    // If API not yet implemented, use empty array
                    this.invitations = [];
                }
            } catch (error) {
                console.error('Error loading invitations:', error);
                this.dispatchNotification('Failed to load invitations', 'error');
            } finally {
                this.isLoadingInvitations = false;
            }
        },
        
        /**
         * Load documents list
         */
        async loadDocuments() {
            this.isLoadingDocuments = true;
            
            try {
                const response = await fetch('/admin/documents', {
                    method: 'GET',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.documents = data.documents || [];
                } else {
                    // If API not yet implemented, use empty array
                    this.documents = [];
                }
            } catch (error) {
                console.error('Error loading documents:', error);
                this.dispatchNotification('Failed to load documents', 'error');
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
                const response = await fetch(`/admin/logs?level=${this.logLevel}`, {
                    method: 'GET',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.logs = data.logs || [];
                } else {
                    // If API not yet implemented, use empty array
                    this.logs = [];
                }
            } catch (error) {
                console.error('Error loading logs:', error);
                this.dispatchNotification('Failed to load logs', 'error');
            } finally {
                this.isLoadingLogs = false;
            }
        },
        
        /**
         * Load system configuration
         */
        async loadSystemConfig() {
            this.isLoadingConfig = true;
            
            try {
                const response = await fetch('/admin/config', {
                    method: 'GET',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Don't populate API key for security reasons
                    this.configForm = {
                        azureEndpoint: data.config.azure_endpoint || '',
                        azureApiKey: '', // Don't load API key
                        maxUploadSize: data.config.max_upload_size || 50,
                        defaultSearchEngine: data.config.default_search_engine || 'google',
                        logLevel: data.config.log_level || 'INFO'
                    };
                } else {
                    // Set default values if API not yet implemented
                    this.configForm = {
                        azureEndpoint: '',
                        azureApiKey: '',
                        maxUploadSize: 50,
                        defaultSearchEngine: 'google',
                        logLevel: 'INFO'
                    };
                }
            } catch (error) {
                console.error('Error loading config:', error);
                this.dispatchNotification('Failed to load configuration', 'error');
            } finally {
                this.isLoadingConfig = false;
            }
        },
        
        /**
         * Save system configuration
         */
        async saveSystemConfig() {
            try {
                const response = await fetch('/admin/config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        azure_endpoint: this.configForm.azureEndpoint,
                        azure_api_key: this.configForm.azureApiKey || undefined, // Only include if provided
                        max_upload_size: this.configForm.maxUploadSize,
                        default_search_engine: this.configForm.defaultSearchEngine,
                        log_level: this.configForm.logLevel
                    })
                });
                
                if (response.ok) {
                    this.configSuccess = 'Configuration saved successfully';
                    this.configError = null;
                    
                    // Clear API key field
                    this.configForm.azureApiKey = '';
                    
                    // Clear success message after 3 seconds
                    setTimeout(() => {
                        this.configSuccess = null;
                    }, 3000);
                } else {
                    const data = await response.json();
                    this.configError = data.error || 'Failed to save configuration';
                    this.configSuccess = null;
                }
            } catch (error) {
                console.error('Error saving config:', error);
                this.configError = 'An unexpected error occurred';
                this.configSuccess = null;
            }
        },
        
        /**
         * Open the user edit modal
         */
        openEditUserModal(user = null) {
            this.selectedUser = user;
            
            if (user) {
                // Edit existing user
                this.userForm = {
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    active: user.active
                };
            } else {
                // Create new user (invitation)
                this.userForm = {
                    username: '',
                    email: '',
                    role: 'user',
                    active: true
                };
            }
            
            this.userSuccess = null;
            this.userError = null;
            this.showEditUserModal = true;
        },
        
        /**
         * Save user changes or send invitation
         */
        async saveUser() {
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
                        this.userSuccess = 'User updated successfully';
                        this.userError = null;
                        
                        // Refresh user list
                        await this.loadUsers();
                        
                        // Close modal after a delay
                        setTimeout(() => {
                            this.showEditUserModal = false;
                        }, 1500);
                    } else {
                        const data = await response.json();
                        this.userError = data.error || 'Failed to update user';
                        this.userSuccess = null;
                    }
                } else {
                    // Send invitation
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
                        this.userSuccess = `Invitation sent to ${this.userForm.email}`;
                        this.userError = null;
                        
                        // Refresh invitation list
                        await this.loadInvitations();
                        
                        // Close modal after a delay
                        setTimeout(() => {
                            this.showEditUserModal = false;
                        }, 1500);
                    } else {
                        const data = await response.json();
                        this.userError = data.error || 'Failed to send invitation';
                        this.userSuccess = null;
                    }
                }
            } catch (error) {
                console.error('Error saving user:', error);
                this.userError = 'An unexpected error occurred';
                this.userSuccess = null;
            }
        },
        
        /**
         * Send an invitation
         */
        async sendInvitation() {
            if (!this.inviteEmail) return;
            
            this.isInviting = true;
            
            try {
                const response = await fetch('/auth/invite', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email: this.inviteEmail
                    })
                });
                
                if (response.ok) {
                    this.dispatchNotification(`Invitation sent to ${this.inviteEmail}`, 'success');
                    this.inviteEmail = ''; // Clear the field
                    
                    // Refresh invitation list
                    await this.loadInvitations();
                } else {
                    const data = await response.json();
                    this.dispatchNotification(data.error || 'Failed to send invitation', 'error');
                }
            } catch (error) {
                console.error('Error sending invitation:', error);
                this.dispatchNotification('Failed to send invitation', 'error');
            } finally {
                this.isInviting = false;
            }
        },
        
        /**
         * Show confirmation modal
         */
        confirmAction(action, title, message, param = null) {
            this.confirmModal = {
                show: true,
                title: title,
                message: message,
                action: action,
                param: param,
                confirmText: action === 'deleteUser' ? 'Delete' : 'Confirm'
            };
        },
        
        /**
         * Execute the confirmed action
         */
        async executeConfirmedAction() {
            const { action, param } = this.confirmModal;
            
            // Hide the modal
            this.confirmModal.show = false;
            
            switch (action) {
                case 'deleteUser':
                    await this.deleteUser(param);
                    break;
                case 'revokeInvitation':
                    await this.revokeInvitation(param);
                    break;
                case 'deleteDocument':
                    await this.deleteDocument(param);
                    break;
                case 'clearLogs':
                    await this.clearLogs();
                    break;
            }
        },
        
        /**
         * Delete a user
         */
        async deleteUser(userId) {
            try {
                const response = await fetch(`/admin/users/${userId}`, {
                    method: 'DELETE',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    this.dispatchNotification('User deleted successfully', 'success');
                    
                    // Remove from local list
                    this.users = this.users.filter(user => user.user_id !== userId);
                } else {
                    const data = await response.json();
                    this.dispatchNotification(data.error || 'Failed to delete user', 'error');
                }
            } catch (error) {
                console.error('Error deleting user:', error);
                this.dispatchNotification('Failed to delete user', 'error');
            }
        },
        
        /**
         * Revoke an invitation
         */
        async revokeInvitation(invitationId) {
            try {
                const response = await fetch(`/admin/invitations/${invitationId}`, {
                    method: 'DELETE',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    this.dispatchNotification('Invitation revoked successfully', 'success');
                    
                    // Remove from local list
                    this.invitations = this.invitations.filter(inv => inv.invitation_id !== invitationId);
                } else {
                    const data = await response.json();
                    this.dispatchNotification(data.error || 'Failed to revoke invitation', 'error');
                }
            } catch (error) {
                console.error('Error revoking invitation:', error);
                this.dispatchNotification('Failed to revoke invitation', 'error');
            }
        },
        
        /**
         * Delete a document
         */
        async deleteDocument(docId) {
            try {
                const response = await fetch(`/admin/documents/${docId}`, {
                    method: 'DELETE',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    this.dispatchNotification('Document deleted successfully', 'success');
                    
                    // Remove from local list
                    this.documents = this.documents.filter(doc => doc.doc_id !== docId);
                } else {
                    const data = await response.json();
                    this.dispatchNotification(data.error || 'Failed to delete document', 'error');
                }
            } catch (error) {
                console.error('Error deleting document:', error);
                this.dispatchNotification('Failed to delete document', 'error');
            }
        },
        
        /**
         * Clear system logs
         */
        async clearLogs() {
            try {
                const response = await fetch('/admin/logs', {
                    method: 'DELETE',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    this.dispatchNotification('Logs cleared successfully', 'success');
                    this.logs = [];
                } else {
                    const data = await response.json();
                    this.dispatchNotification(data.error || 'Failed to clear logs', 'error');
                }
            } catch (error) {
                console.error('Error clearing logs:', error);
                this.dispatchNotification('Failed to clear logs', 'error');
            }
        },
        
        /**
         * Download a document
         */
        async downloadDocument(docId, fileName) {
            try {
                window.open(`/admin/documents/${docId}/download`, '_blank');
            } catch (error) {
                console.error('Error downloading document:', error);
                this.dispatchNotification('Failed to download document', 'error');
            }
        },
        
        /**
         * Copy invitation link to clipboard
         */
        copyToClipboard(text) {
            navigator.clipboard.writeText(text)
                .then(() => {
                    this.dispatchNotification('Copied to clipboard', 'success');
                })
                .catch(err => {
                    console.error('Could not copy text: ', err);
                    this.dispatchNotification('Failed to copy to clipboard', 'error');
                });
        },
        
        /**
         * Get status badge class based on active status
         */
        getStatusClass(isActive) {
            return isActive
                ? 'bg-success-100 text-success-800'
                : 'bg-danger-100 text-danger-800';
        },
        
        /**
         * Get file type badge class
         */
        getFileTypeBadgeClass(fileName) {
            const extension = this.getFileExtension(fileName);
            
            switch (extension) {
                case 'pdf':
                    return 'bg-danger-100 text-danger-800';
                case 'txt':
                    return 'bg-secondary-100 text-secondary-800';
                case 'docx':
                case 'doc':
                    return 'bg-primary-100 text-primary-800';
                case 'jpg':
                case 'jpeg':
                case 'png':
                    return 'bg-success-100 text-success-800';
                default:
                    return 'bg-warning-100 text-warning-800';
            }
        },
        
        /**
         * Get file extension
         */
        getFileExtension(fileName) {
            return fileName.split('.').pop().toLowerCase();
        },
        
        /**
         * Get file type label
         */
        getFileType(fileName) {
            const extension = this.getFileExtension(fileName);
            return extension.toUpperCase();
        },
        
        /**
         * Get file icon based on file type
         */
        getFileIcon(fileName) {
            const extension = this.getFileExtension(fileName);
            
            switch (extension) {
                case 'pdf':
                    return 'fas fa-file-pdf';
                case 'txt':
                    return 'fas fa-file-alt';
                case 'docx':
                case 'doc':
                    return 'fas fa-file-word';
                case 'xlsx':
                case 'xls':
                    return 'fas fa-file-excel';
                case 'pptx':
                case 'ppt':
                    return 'fas fa-file-powerpoint';
                case 'jpg':
                case 'jpeg':
                case 'png':
                case 'gif':
                    return 'fas fa-file-image';
                default:
                    return 'fas fa-file';
            }
        },
        
        /**
         * Get log level icon
         */
        getLogLevelIcon(level) {
            switch (level.toLowerCase()) {
                case 'error':
                    return 'fas fa-times-circle';
                case 'warning':
                    return 'fas fa-exclamation-triangle';
                case 'info':
                    return 'fas fa-info-circle';
                case 'debug':
                    return 'fas fa-bug';
                default:
                    return 'fas fa-dot-circle';
            }
        },
        
        /**
         * Get log level text class
         */
        getLogLevelClass(level) {
            switch (level.toLowerCase()) {
                case 'error':
                    return 'text-danger-600';
                case 'warning':
                    return 'text-warning-600';
                case 'info':
                    return 'text-primary-600';
                case 'debug':
                    return 'text-secondary-600';
                default:
                    return 'text-secondary-500';
            }
        },
        
        /**
         * Format date for display
         */
        formatDate(dateString) {
            if (!dateString) return '';
            
            const date = new Date(dateString);
            
            // Check if date is valid
            if (isNaN(date.getTime())) return '';
            
            return date.toLocaleString();
        },
        
        /**
         * Show a notification
         */
        dispatchNotification(message, type = 'info') {
            const event = new CustomEvent('notification', {
                detail: {
                    message,
                    type,
                    id: Date.now()
                }
            });
            window.dispatchEvent(event);
        }
    };
}
