/**
 * Notification Service for Triton AI
 * Manages toast notifications throughout the application
 */

// Wait for Alpine.js to be ready before registering components
document.addEventListener('alpine:init', () => {
    // Register notifications component
    Alpine.data('notifications', function() {
        return {
            notifications: [],
            
            /**
             * Add a new notification
             * @param {string} message - Notification message
             * @param {string} type - Notification type (success, error, warning, info)
             * @param {number} id - Optional ID for the notification
             * @returns {number} The notification ID
             */
            addNotification(message, type = 'info', id = null) {
                const notificationId = id || Date.now();
                
                // Create the notification
                const notification = {
                    id: notificationId,
                    message,
                    type,
                    timeout: setTimeout(() => {
                        this.removeNotification(notificationId);
                    }, 5000) // Auto-dismiss after 5 seconds
                };
                
                // Add to notifications array
                this.notifications.push(notification);
                
                // Limit to 3 notifications at a time
                if (this.notifications.length > 3) {
                    const oldest = this.notifications.shift();
                    clearTimeout(oldest.timeout);
                }
                
                return notificationId;
            },
            
            /**
             * Remove a notification by ID
             * @param {number} id - Notification ID to remove
             */
            removeNotification(id) {
                const notification = this.notifications.find(n => n.id === id);
                if (notification) {
                    clearTimeout(notification.timeout);
                    this.notifications = this.notifications.filter(n => n.id !== id);
                }
            },
            
            /**
             * Get the appropriate icon class for a notification type
             * @param {string} type - Notification type
             * @returns {string} FontAwesome icon class
             */
            getIconClass(type) {
                switch (type) {
                    case 'success': return 'fas fa-check-circle';
                    case 'error': return 'fas fa-exclamation-circle';
                    case 'warning': return 'fas fa-exclamation-triangle';
                    default: return 'fas fa-info-circle';
                }
            },
            
            /**
             * Get the appropriate background class for a notification type
             * @param {string} type - Notification type
             * @returns {string} CSS class string
             */
            getBackgroundClass(type) {
                switch (type) {
                    case 'success': return 'bg-success-50 border border-success-200 text-success-700';
                    case 'error': return 'bg-danger-50 border border-danger-200 text-danger-700';
                    case 'warning': return 'bg-warning-50 border border-warning-200 text-warning-700';
                    default: return 'bg-primary-50 border border-primary-200 text-primary-700';
                }
            }
        };
    });

    // Register Alpine.js components
    Alpine.data('chatApp', function() {
        return {
            // Authentication and user state
            isAuthenticated: false,
            isCheckingAuth: true,
            userInitials: '',
            userName: '',
            userEmail: '',
            userRole: '',
            
            // UI state
            state: 'welcome', // welcome, loading, chat
            sidebarOpen: window.innerWidth >= 1024, // Default open on desktop
            isLoading: false,
            isThinking: false,
            isRegenerating: false,
            isUploading: false,
            
            // Content
            searchQuery: '',
            filteredConversations: [],
            conversations: [],
            currentConversationId: null,
            currentMessages: [],
            newMessage: '',
            
            // Features and models
            selectedModel: 'openai/gpt-4o',
            features: {
                search: false,
                reasoning: true,
                deep_research: false
            },
            modelCategories: [
                {
                    name: "OpenAI Models",
                    models: [
                        { id: "openai/gpt-4o", name: "GPT-4o" },
                        { id: "openai/gpt-4", name: "GPT-4" },
                        { id: "openai/gpt-3.5-turbo", name: "GPT-3.5 Turbo" }
                    ]
                },
                {
                    name: "Anthropic Models",
                    models: [
                        { id: "anthropic/claude-3-opus", name: "Claude 3 Opus" },
                        { id: "anthropic/claude-3-sonnet", name: "Claude 3 Sonnet" },
                        { id: "anthropic/claude-3-haiku", name: "Claude 3 Haiku" }
                    ]
                }
            ],
            
            // Modals
            showDeleteModal: false,
            showRenameModal: false,
            showInviteModal: false,
            showDocumentModal: false,
            showKeyboardShortcuts: false,
            showInfoModal: false,
            
            // Form data
            conversationToDelete: null,
            newConversationName: '',
            inviteEmail: '',
            inviteSuccess: false,
            inviteError: null,
            invitationUrl: '',
            isInviting: false,
            
            // Document handling
            selectedFile: null,
            documentError: null,
            dragOver: false,
            
            /**
             * Initialize the application
             */
            initialize() {
                console.log("Initializing chat application");
                // Implementation from app.js will be used
            },
            
            // Add stubs for all other functions used in the templates
            // These will be replaced by the actual implementations from app.js
            toggleSidebar() {},
            startNewChat() {},
            sendMessage() {},
            searchConversations() {},
            loadConversation() {},
            openRenameModal() {},
            confirmDelete() {},
            renameConversation() {},
            deleteConversation() {},
            handleEnterKey() {},
            copyToClipboard() {},
            regenerateResponse() {},
            closeInviteModal() {},
            openDocumentUpload() {},
            handleFileSelect() {},
            handleFileDrop() {},
            uploadDocument() {},
            sendInvitation() {},
            logout() {},
            formatMarkdown() {},
            formatTime() {},
            formatDate() {},
            formatFileSize() {},
            scrollToBottom() {},
            saveFeaturePreferences() {}
        };
    });
    
    // Register admin panel component
    Alpine.data('adminPanel', function() {
        return {
            isAuthenticated: false,
            isCheckingAuth: true,
            userInitials: '',
            userName: '',
            activeTab: 'overview',
            // Other admin properties with default values
            initialize() {
                console.log("Initializing admin panel");
                // Implementation will come from admin.js
            }
        };
    });
});

/**
 * Helper function to dispatch global notification events
 * Can be used anywhere in the application to show notifications
 * @param {string} message - Notification message
 * @param {string} type - Notification type (success, error, warning, info)
 */
function dispatchNotification(message, type = 'info') {
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
