/**
 * Main Chat Application
 * Provides the core chat functionality for Triton AI
 */

// Register chatApp with Alpine when it's ready
document.addEventListener('alpine:init', () => {
    Alpine.data('chatApp', chatApp);
});

function chatApp() {
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
        selectedModel: 'microsoft/MAI-DS-R1',
        features: {
            search: false,
            reasoning: true,
            deep_research: false,
            document: false
        },
        modelCategories: [], // Will be populated from API
        isLoadingModels: false,
        modelsError: null,
        
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
        async initialize() {
            try {
                this.isCheckingAuth = true;
                
                // Check authentication status
                const response = await fetch('/auth/me', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.isAuthenticated = true;
                    this.userName = data.user.username;
                    this.userEmail = data.user.email;
                    this.userRole = data.user.role;
                    this.userInitials = this.getInitials(data.user.username);
                    
                    // Load models from API
                    await this.loadModels();
                    
                    // Load conversations
                    await this.loadConversations();
                    
                    // Set up keyboard shortcuts
                    this.setupKeyboardShortcuts();
                    
                    // Load saved feature preferences from localStorage
                    this.loadFeaturePreferences();
                    
                    // Apply theme from settings
                    this.applyTheme();
                } else {
                    this.isAuthenticated = false;
                }
            } catch (error) {
                console.error('Initialization error:', error);
                this.isAuthenticated = false;
            } finally {
                this.isCheckingAuth = false;
            }
            
            // Add keyboard shortcut listener for model panel toggle
            document.addEventListener('keydown', (e) => {
                // Ctrl+M to toggle model panel
                if (e.ctrlKey && e.key === 'm') {
                    e.preventDefault();
                    const panelState = localStorage.getItem('modelPanelExpanded') === 'false' ? false : true;
                    localStorage.setItem('modelPanelExpanded', !panelState);
                    // Force Alpine to re-evaluate the panel state
                    document.querySelector('#modelFeaturesPanel')?.dispatchEvent(new CustomEvent('panel-toggle'));
                }
            });
        },
        
        /**
         * Apply theme from localStorage settings
         */
        applyTheme() {
            const savedSettings = localStorage.getItem('triton_settings');
            if (savedSettings) {
                const settings = JSON.parse(savedSettings);
                if (settings.theme) {
                    const theme = settings.theme;
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
                }
            }
        },
        
        /**
         * Load available models from backend
         */
        async loadModels() {
            this.isLoadingModels = true;
            this.modelsError = null;
            
            try {
                const response = await fetch('/models', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    if (data.models && Object.keys(data.models).length > 0) {
                        // Transform backend model data to frontend format
                        const modelsByProvider = {};
                        
                        // Group models by provider
                        Object.entries(data.models).forEach(([modelId, modelInfo]) => {
                            const provider = modelId.split('/')[0] || 'Default';
                            
                            if (!modelsByProvider[provider]) {
                                modelsByProvider[provider] = [];
                            }
                            
                            modelsByProvider[provider].push({
                                id: modelId,
                                name: modelInfo.name || modelId.split('/')[1] || modelId,
                                description: modelInfo.description || '',
                                tokens: modelInfo.tokens || {}
                            });
                        });
                        
                        // Convert to array format needed by the UI
                        this.modelCategories = Object.entries(modelsByProvider).map(([provider, models]) => ({
                            name: this.formatProviderName(provider),
                            models: models
                        }));
                        
                        // If no model is selected or the selected model isn't available, select the first one
                        if (!this.selectedModel || !this.isModelAvailable(this.selectedModel)) {
                            if (this.modelCategories.length > 0 && this.modelCategories[0].models.length > 0) {
                                this.selectedModel = this.modelCategories[0].models[0].id;
                            }
                        }
                        
                        // Load saved model preference from localStorage
                        const savedSettings = localStorage.getItem('triton_settings');
                        if (savedSettings) {
                            const settings = JSON.parse(savedSettings);
                            if (settings.defaultModel && this.isModelAvailable(settings.defaultModel)) {
                                this.selectedModel = settings.defaultModel;
                            }
                        }
                    } else {
                        // Fallback to hardcoded models if API returns no models
                        this.setFallbackModels();
                    }
                } else {
                    // API error, use fallback models
                    this.modelsError = 'Failed to load models from API';
                    this.setFallbackModels();
                }
            } catch (error) {
                console.error('Error loading models:', error);
                this.modelsError = 'Error connecting to the model service';
                this.setFallbackModels();
            } finally {
                this.isLoadingModels = false;
            }
        },
        
        /**
         * Format provider name to be more user-friendly
         */
        formatProviderName(provider) {
            const capitalizedProvider = provider.charAt(0).toUpperCase() + provider.slice(1);
            
            // Map known providers to better display names
            const providerNames = {
                'openai': 'OpenAI',
                'anthropic': 'Anthropic',
                'azure': 'Azure OpenAI',
                'microsoft': 'Microsoft',
                'meta': 'Meta AI',
                'llama': 'Llama',
                'mistral': 'Mistral AI',
                'cohere': 'Cohere'
            };
            
            return providerNames[provider.toLowerCase()] || capitalizedProvider;
        },
        
        /**
         * Check if a model is available in the loaded models
         */
        isModelAvailable(modelId) {
            return this.modelCategories.some(category => 
                category.models.some(model => model.id === modelId)
            );
        },
        
        /**
         * Set fallback models in case API fails
         */
        setFallbackModels() {
            this.modelCategories = [
                {
                    name: "Microsoft Models",
                    models: [
                        { id: "microsoft/MAI-DS-R1", name: "Microsoft MAI-DS-R1" },
                        { id: "microsoft/Phi-4-reasoning", name: "Phi-4 Reasoning" },
                        { id: "microsoft/Phi-4-mini-reasoning", name: "Phi-4 Mini Reasoning" }
                    ]
                },
                {
                    name: "OpenAI Models",
                    models: [
                        { id: "openai/gpt-4o", name: "GPT-4o" },
                        { id: "openai/gpt-4.1", name: "GPT-4.1" },
                        { id: "openai/o4-mini", name: "O4 Mini" },
                        { id: "openai/o3", name: "O3" }
                    ]
                },
                {
                    name: "Other Models",
                    models: [
                        { id: "meta/Llama-4-Maverick-17B-128E-Instruct-FP8", name: "Llama 4 Maverick" },
                        { id: "cohere/cohere-command-a", name: "Cohere Command A" },
                        { id: "cohere/Cohere-command-r-plus-08-2024", name: "Cohere Command R+" }
                    ]
                }
            ];
        },
        
        /**
         * Load user feature preferences from localStorage
         */
        loadFeaturePreferences() {
            try {
                const savedPreferences = localStorage.getItem('triton_features');
                if (savedPreferences) {
                    const preferences = JSON.parse(savedPreferences);
                    
                    // Update features while maintaining any missing defaults
                    this.features = { ...this.features, ...preferences };
                }
                
                // Also check settings for default features
                const savedSettings = localStorage.getItem('triton_settings');
                if (savedSettings) {
                    const settings = JSON.parse(savedSettings);
                    if (settings.defaultFeatures) {
                        // Apply default features if no custom preferences
                        if (!savedPreferences) {
                            this.features = { ...this.features, ...settings.defaultFeatures };
                        }
                    }
                }
            } catch (error) {
                console.error('Error loading feature preferences:', error);
            }
        },
        
        /**
         * Save feature preferences to localStorage
         */
        saveFeaturePreferences() {
            try {
                localStorage.setItem('triton_features', JSON.stringify(this.features));
                this.dispatchNotification('Preferences updated', 'success');
            } catch (error) {
                console.error('Error saving feature preferences:', error);
            }
        },
        
        /**
         * Get user initials for avatar display
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
         * Load conversation list from API
         */
        async loadConversations() {
            try {
                this.isLoading = true;
                
                const response = await fetch('/conversations', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.conversations = data.conversations || [];
                    this.filteredConversations = [...this.conversations];
                    
                    // Check if URL has a conversation parameter
                    const urlParams = new URLSearchParams(window.location.search);
                    const conversationId = urlParams.get('conversation');
                    
                    if (conversationId) {
                        await this.loadConversation(conversationId);
                    }
                } else {
                    console.error('Failed to load conversations');
                    this.dispatchNotification('Failed to load conversations', 'error');
                }
            } catch (error) {
                console.error('Error loading conversations:', error);
                this.dispatchNotification('Error loading conversations', 'error');
            } finally {
                this.isLoading = false;
            }
        },
        
        /**
         * Search conversations by title or content
         */
        searchConversations() {
            if (!this.searchQuery.trim()) {
                this.filteredConversations = [...this.conversations];
                return;
            }
            
            const query = this.searchQuery.toLowerCase();
            this.filteredConversations = this.conversations.filter(conversation => {
                const nameMatch = (conversation.conversation_name || '').toLowerCase().includes(query);
                const contentMatch = (conversation.first_message || '').toLowerCase().includes(query);
                return nameMatch || contentMatch;
            });
        },
        
        /**
         * Load a specific conversation
         */
        async loadConversation(conversationId) {
            if (this.isLoading) return;
            this.isLoading = true;
            this.state = 'loading';
            
            try {
                const response = await fetch(`/conversations/${conversationId}`, {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Update UI state
                    this.currentConversationId = data.conversation_id;
                    this.currentMessages = data.messages.map(msg => {
                        // Ensure search_context is always an array
                        if (!msg.search_context || !Array.isArray(msg.search_context)) {
                            msg.search_context = [];
                        }
                        return msg;
                    });
                    
                    // Update URL to include conversation ID
                    window.history.replaceState({}, '', `/?conversation=${conversationId}`);
                    
                    // Set state to chat
                    this.state = 'chat';
                    
                    // Scroll to bottom after the DOM updates
                    this.$nextTick(() => {
                        this.scrollToBottom();
                        this.renderCodeAndMath();
                    });
                } else {
                    const errorData = await response.json();
                    this.dispatchNotification(errorData.error || 'Failed to load conversation', 'error');
                    this.state = 'welcome';
                }
            } catch (error) {
                this.dispatchNotification('Failed to load conversation', 'error');
                this.state = 'welcome';
            } finally {
                this.isLoading = false;
            }
        },
        
        /**
         * Start a new chat conversation
         */
        async startNewChat() {
            if (this.isLoading) return;
            
            // Clear current conversation data
            this.currentConversationId = null;
            this.currentMessages = [];
            this.newMessage = '';
            
            // Update URL
            window.history.replaceState({}, '', window.location.pathname);
            
            // Set state to chat (empty conversation)
            this.state = 'chat';
            
            // Focus the input field
            this.$nextTick(() => {
                const messageInput = document.querySelector('textarea');
                if (messageInput) messageInput.focus();
            });
        },
        
        /**
         * Toggle sidebar visibility
         */
        toggleSidebar() {
            this.sidebarOpen = !this.sidebarOpen;
        },
        
        /**
         * Send a new message in the current conversation
         */
        async sendMessage() {
            if (this.isThinking || this.isRegenerating || !this.newMessage.trim()) return;
            
            const message = this.newMessage.trim();
            this.newMessage = '';
            this.isThinking = true;
            
            // Optimistically add user message to the UI
            const tempId = Date.now().toString();
            const messageObj = {
                message_id: tempId,
                timestamp: new Date().toISOString(),
                user_message: message,
                assistant_message: '',
                model: this.selectedModel,
                search_context: [] // Ensure this is always defined
            };
            
            this.currentMessages.push(messageObj);
            
            // Scroll to bottom after the DOM updates
            this.$nextTick(() => {
                this.scrollToBottom();
            });
            
            try {
                const payload = {
                    message: message,
                    conversation_id: this.currentConversationId,
                    model: this.selectedModel,
                    features: this.features
                };
                
                // Add document IDs if document feature is enabled
                if (this.features.document && this.selectedDocuments && this.selectedDocuments.length > 0) {
                    payload.document_ids = this.selectedDocuments;
                }
                
                const response = await fetch('/chat', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(payload)
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Set conversation ID if this is a new conversation
                    if (!this.currentConversationId) {
                        this.currentConversationId = data.conversation_id;
                        window.history.replaceState({}, '', `/?conversation=${data.conversation_id}`);
                        
                        // Add to conversations list
                        await this.loadConversations();
                    }
                    
                    // Update the message with AI response
                    const messageIndex = this.currentMessages.findIndex(m => m.message_id === tempId);
                    if (messageIndex >= 0) {
                        this.currentMessages[messageIndex].assistant_message = data.message;
                        this.currentMessages[messageIndex].reasoning = data.reasoning || '';
                        this.currentMessages[messageIndex].search_context = Array.isArray(data.search_results) ? data.search_results : [];
                        
                        // Re-render code highlighting and math after the DOM updates
                        this.$nextTick(() => {
                            this.renderCodeAndMath();
                            this.scrollToBottom();
                        });
                    }
                } else {
                    // Handle error
                    this.dispatchNotification(data.error || 'Failed to get response', 'error');
                    
                    // Remove the temporary message
                    this.currentMessages = this.currentMessages.filter(m => m.message_id !== tempId);
                }
            } catch (error) {
                this.dispatchNotification('Failed to send message', 'error');
                
                // Remove the temporary message
                this.currentMessages = this.currentMessages.filter(m => m.message_id !== tempId);
            } finally {
                this.isThinking = false;
            }
        },
        
        /**
         * Regenerate the AI response for a specific message
         */
        async regenerateResponse(index) {
            if (this.isThinking || this.isRegenerating) return;
            
            this.isRegenerating = true;
            const messageToRegenerate = this.currentMessages[index];
            
            try {
                const response = await fetch('/chat', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        message: messageToRegenerate.user_message,
                        conversation_id: this.currentConversationId,
                        model: this.selectedModel,
                        features: this.features,
                        regenerate: true
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Update the message with the new response
                    this.currentMessages[index].assistant_message = data.message;
                    this.currentMessages[index].reasoning = data.reasoning;
                    this.currentMessages[index].search_context = data.search_results;
                    
                    // Rerender code blocks and math
                    this.$nextTick(() => {
                        this.renderCodeAndMath();
                    });
                } else {
                    const errorData = await response.json();
                    console.error('Error regenerating response:', errorData);
                    this.dispatchNotification(errorData.error || 'Failed to regenerate response', 'error');
                }
            } catch (error) {
                console.error('Error regenerating response:', error);
                this.dispatchNotification('Failed to regenerate response', 'error');
            } finally {
                this.isRegenerating = false;
            }
        },
        
        /**
         * Format markdown content with syntax highlighting and math rendering
         */
        formatMarkdown(content) {
            if (!content) return '';
            
            // Sanitize content to prevent XSS
            const sanitizedContent = DOMPurify.sanitize(marked.parse(content));
            
            return sanitizedContent;
        },
        
        /**
         * Re-render code highlighting and math after content updates
         */
        renderCodeAndMath() {
            try {
                // Apply code syntax highlighting
                document.querySelectorAll('pre code').forEach((block) => {
                    hljs.highlightElement(block);
                });
                
                // Render math expressions
                if (typeof renderMathInElement === 'function') {
                    renderMathInElement(document.body, {
                        delimiters: [
                            {left: '$$', right: '$$', display: true},
                            {left: '$', right: '$', display: false},
                            {left: '\\(', right: '\\)', display: false},
                            {left: '\\[', right: '\\]', display: true}
                        ]
                    });
                }
            } catch (error) {
                console.error('Error rendering code/math:', error);
            }
        },
        
        /**
         * Copy text to clipboard
         */
        copyToClipboard(text) {
            navigator.clipboard.writeText(text)
                .then(() => {
                    this.dispatchNotification('Copied to clipboard', 'success');
                })
                .catch(err => {
                    console.error('Failed to copy: ', err);
                    this.dispatchNotification('Failed to copy to clipboard', 'error');
                });
        },
        
        /**
         * Scroll to the bottom of the messages container
         */
        scrollToBottom() {
            const messagesContainer = document.getElementById('messages');
            if (messagesContainer) {
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
            }
        },
        
        /**
         * Handle scroll in messages container (for loading more messages)
         */
        handleScroll(event) {
            // Implement infinite scroll for loading more messages if needed
        },
        
        /**
         * Format date for display using user's local timezone
         */
        formatDate(dateString) {
            return DateFormatter.formatDate(dateString);
        },
        
        /**
         * Format time for display using user's local timezone
         */
        formatTime(dateString) {
            return DateFormatter.formatTime(dateString ? new Date(dateString) : null);
        },
        
        /**
         * Format file size in human-readable format
         */
        formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },
        
        /**
         * Open the document upload modal
         */
        openDocumentUpload() {
            this.selectedFile = null;
            this.documentError = null;
            this.showDocumentModal = true;
        },
        
        /**
         * Handle file selection
         */
        handleFileSelect(event) {
            const file = event.target.files[0];
            if (file) {
                this.validateAndSetFile(file);
            }
        },
        
        /**
         * Handle file drop
         */
        handleFileDrop(event) {
            this.dragOver = false;
            const file = event.dataTransfer.files[0];
            if (file) {
                this.validateAndSetFile(file);
            }
        },
        
        /**
         * Validate and set selected file
         */
        validateAndSetFile(file) {
            // Check file size
            const maxSize = 50 * 1024 * 1024; // 50MB
            if (file.size > maxSize) {
                this.documentError = 'File size exceeds the 50MB limit';
                return;
            }
            
            // Check file type (basic validation)
            const validTypes = ['.pdf', '.docx', '.doc', '.txt', '.md', '.jpg', '.jpeg', '.png'];
            const fileExt = '.' + file.name.split('.').pop().toLowerCase();
            
            if (!validTypes.includes(fileExt)) {
                this.documentError = 'File type not supported';
                return;
            }
            
            this.selectedFile = file;
            this.documentError = null;
        },
        
        /**
         * Upload selected document
         */
        async uploadDocument() {
            if (!this.selectedFile) return;
            
            this.isUploading = true;
            this.documentError = null;
            
            try {
                const formData = new FormData();
                formData.append('file', this.selectedFile);
                
                // Add conversation ID if we're in a conversation
                if (this.currentConversationId) {
                    formData.append('conversation_id', this.currentConversationId);
                }
                
                const response = await fetch('/upload-document', {
                    method: 'POST',
                    credentials: 'include',
                    body: formData
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Close the modal
                    this.showDocumentModal = false;
                    this.selectedFile = null;
                    
                    // Display success message
                    this.dispatchNotification('Document uploaded successfully', 'success');
                    
                    // If we have a response message, add it to the conversation
                    if (data.message) {
                        // Create a new conversation if needed
                        if (!this.currentConversationId && data.conversation_id) {
                            this.currentConversationId = data.conversation_id;
                            
                            // Update URL
                            window.history.replaceState(
                                {},
                                '',
                                `${window.location.pathname}?conversation=${data.conversation_id}`
                            );
                            
                            // Reload conversations list
                            await this.loadConversations();
                        }
                        
                        // Add system message about the document
                        const messageObj = {
                            message_id: Date.now().toString(),
                            timestamp: new Date().toISOString(),
                            user_message: `[Document uploaded: ${this.selectedFile.name}]`,
                            assistant_message: data.message,
                            model: this.selectedModel
                        };
                        
                        this.currentMessages.push(messageObj);
                        
                        // Update state and scroll
                        this.state = 'chat';
                        this.$nextTick(() => {
                            this.scrollToBottom();
                            this.renderCodeAndMath();
                        });
                    }
                } else {
                    const errorData = await response.json();
                    this.documentError = errorData.error || 'Failed to upload document';
                }
            } catch (error) {
                console.error('Error uploading document:', error);
                this.documentError = 'Failed to upload document';
            } finally {
                this.isUploading = false;
            }
        },
        
        /**
         * Open rename modal for a conversation
         */
        openRenameModal(conversation) {
            this.conversationToRename = conversation.conversation_id;
            this.newConversationName = conversation.conversation_name || '';
            this.showRenameModal = true;
        },
        
        /**
         * Rename the selected conversation
         */
        async renameConversation() {
            if (!this.conversationToRename || !this.newConversationName.trim()) return;
            
            try {
                const response = await fetch(`/conversations/${this.conversationToRename}`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name: this.newConversationName.trim()
                    })
                });
                
                if (response.ok) {
                    // Update local data
                    const index = this.conversations.findIndex(c => c.conversation_id === this.conversationToRename);
                    if (index !== -1) {
                        this.conversations[index].conversation_name = this.newConversationName.trim();
                        this.filteredConversations = [...this.conversations];
                    }
                    
                    this.dispatchNotification('Conversation renamed successfully', 'success');
                } else {
                    const errorData = await response.json();
                    this.dispatchNotification(errorData.error || 'Failed to rename conversation', 'error');
                }
            } catch (error) {
                console.error('Error renaming conversation:', error);
                this.dispatchNotification('Failed to rename conversation', 'error');
            } finally {
                this.showRenameModal = false;
                this.conversationToRename = null;
                this.newConversationName = '';
            }
        },
        
        /**
         * Show delete confirmation modal
         */
        confirmDelete(conversationId) {
            this.conversationToDelete = conversationId;
            this.showDeleteModal = true;
        },
        
        /**
         * Delete the selected conversation
         */
        async deleteConversation(conversationId) {
            if (!conversationId) return;
            
            try {
                const response = await fetch(`/conversations/${conversationId}`, {
                    method: 'DELETE',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    // Remove from local data
                    this.conversations = this.conversations.filter(c => c.conversation_id !== conversationId);
                    this.filteredConversations = [...this.conversations];
                    
                    // If the deleted conversation was the current one, go back to welcome screen
                    if (this.currentConversationId === conversationId) {
                        this.currentConversationId = null;
                        this.currentMessages = [];
                        this.state = 'welcome';
                        window.history.replaceState({}, '', window.location.pathname);
                    }
                    
                    this.dispatchNotification('Conversation deleted successfully', 'success');
                } else {
                    const errorData = await response.json();
                    this.dispatchNotification(errorData.error || 'Failed to delete conversation', 'error');
                }
            } catch (error) {
                console.error('Error deleting conversation:', error);
                this.dispatchNotification('Failed to delete conversation', 'error');
            } finally {
                this.showDeleteModal = false;
                this.conversationToDelete = null;
            }
        },
        
        /**
         * Handle Enter key in the message input
         */
        handleEnterKey(event) {
            // Send message on Enter, add new line on Shift+Enter
            if (!event.shiftKey) {
                this.sendMessage();
            }
        },
        
        /**
         * Send an invitation to a new user
         */
        async sendInvitation() {
            if (!this.inviteEmail || this.isInviting) return;
            
            this.isInviting = true;
            this.inviteError = null;
            this.inviteSuccess = false;
            this.invitationUrl = '';
            
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
                
                const data = await response.json();
                
                if (response.ok) {
                    this.inviteSuccess = true;
                    this.invitationUrl = data.invitation_url;
                    this.dispatchNotification(`Invitation sent to ${this.inviteEmail}`, 'success');
                } else {
                    this.inviteError = data.error || 'Failed to send invitation';
                }
            } catch (error) {
                console.error('Error sending invitation:', error);
                this.inviteError = 'Failed to send invitation';
            } finally {
                this.isInviting = false;
            }
        },
        
        /**
         * Close the invite modal and reset its state
         */
        closeInviteModal() {
            this.showInviteModal = false;
            this.inviteEmail = '';
            this.inviteError = null;
            this.inviteSuccess = false;
            this.invitationUrl = '';
        },
        
        /**
         * Log out the current user
         */
        async logout() {
            try {
                await fetch('/auth/logout', {
                    method: 'POST',
                    credentials: 'include'
                });
                
                // Redirect to login page
                window.location.href = '/login';
            } catch (error) {
                console.error('Logout error:', error);
                this.dispatchNotification('Failed to log out', 'error');
            }
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
        },
        
        /**
         * Set up keyboard shortcuts
         */
        setupKeyboardShortcuts() {
            document.addEventListener('keydown', (e) => {
                // Ctrl/Cmd + / - Show keyboard shortcuts
                if ((e.ctrlKey || e.metaKey) && e.key === '/') {
                    e.preventDefault();
                    this.showKeyboardShortcuts = true;
                }
                
                // Esc - Close modals
                if (e.key === 'Escape') {
                    this.showDeleteModal = false;
                    this.showRenameModal = false;
                    this.showInviteModal = false;
                    this.showDocumentModal = false;
                    this.showKeyboardShortcuts = false;
                    this.showInfoModal = false;
                }
                
                // Ctrl/Cmd + N - New chat
                if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
                    e.preventDefault();
                    this.startNewChat();
                }
                
                // Ctrl/Cmd + B - Toggle sidebar
                if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
                    e.preventDefault();
                    this.toggleSidebar();
                }
            });
        }
    };
}
