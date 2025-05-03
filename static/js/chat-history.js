function chatHistoryManager() {
    return {
        conversations: [],
        isLoading: true,
        searchQuery: '',
        filteredConversations: [],
        sortBy: 'recent', // 'recent', 'oldest', 'alphabetical'
        
        async initialize() {
            await this.loadConversations();
            this.setupEventListeners();
        },
        
        setupEventListeners() {
            // Listen for conversation updates from other components
            window.addEventListener('conversation-created', () => {
                this.loadConversations();
            });
            
            window.addEventListener('conversation-updated', () => {
                this.loadConversations();
            });
            
            window.addEventListener('conversation-deleted', () => {
                this.loadConversations();
            });
        },
        
        async loadConversations() {
            this.isLoading = true;
            
            try {
                const response = await fetch('/conversations', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.conversations = data.conversations || [];
                    this.filterAndSortConversations();
                } else {
                    console.error('Failed to load conversations');
                }
            } catch (error) {
                console.error('Error loading conversations:', error);
            } finally {
                this.isLoading = false;
            }
        },
        
        filterAndSortConversations() {
            // Filter based on search query
            if (this.searchQuery.trim() !== '') {
                const query = this.searchQuery.toLowerCase();
                this.filteredConversations = this.conversations.filter(
                    conv => (conv.conversation_name && conv.conversation_name.toLowerCase().includes(query)) ||
                           (conv.first_message && conv.first_message.toLowerCase().includes(query))
                );
            } else {
                this.filteredConversations = [...this.conversations];
            }
            
            // Sort conversations
            this.sortConversations();
        },
        
        sortConversations() {
            switch (this.sortBy) {
                case 'recent':
                    this.filteredConversations.sort((a, b) => 
                        new Date(b.last_message || b.created_at) - new Date(a.last_message || a.created_at)
                    );
                    break;
                    
                case 'oldest':
                    this.filteredConversations.sort((a, b) => 
                        new Date(a.created_at) - new Date(b.created_at)
                    );
                    break;
                    
                case 'alphabetical':
                    this.filteredConversations.sort((a, b) => {
                        const nameA = (a.conversation_name || 'Untitled Conversation').toLowerCase();
                        const nameB = (b.conversation_name || 'Untitled Conversation').toLowerCase();
                        return nameA.localeCompare(nameB);
                    });
                    break;
            }
        },
        
        searchConversations() {
            this.filterAndSortConversations();
        },
        
        changeSortOrder(order) {
            this.sortBy = order;
            this.filterAndSortConversations();
        },
        
        async renameConversation(conversationId, newName) {
            try {
                const response = await fetch(`/conversation/${conversationId}/rename`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ name: newName })
                });
                
                if (response.ok) {
                    // Update local data
                    const index = this.conversations.findIndex(c => c.conversation_id === conversationId);
                    if (index !== -1) {
                        this.conversations[index].conversation_name = newName;
                        this.filterAndSortConversations();
                    }
                    
                    return { success: true };
                } else {
                    const data = await response.json();
                    return { success: false, error: data.error || 'Failed to rename conversation' };
                }
            } catch (error) {
                console.error('Error renaming conversation:', error);
                return { success: false, error: 'An unexpected error occurred' };
            }
        },
        
        async deleteConversation(conversationId) {
            try {
                const response = await fetch(`/conversation/${conversationId}`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                    }
                });
                
                if (response.ok) {
                    // Remove from local data
                    this.conversations = this.conversations.filter(c => c.conversation_id !== conversationId);
                    this.filterAndSortConversations();
                    
                    // Dispatch event for other components
                    window.dispatchEvent(new CustomEvent('conversation-deleted', {
                        detail: { conversationId }
                    }));
                    
                    return { success: true };
                } else {
                    const data = await response.json();
                    return { success: false, error: data.error || 'Failed to delete conversation' };
                }
            } catch (error) {
                console.error('Error deleting conversation:', error);
                return { success: false, error: 'An unexpected error occurred' };
            }
        },
        
        async clearAllConversations() {
            try {
                const response = await fetch('/conversations/clear', {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                    }
                });
                
                if (response.ok) {
                    // Clear local data
                    this.conversations = [];
                    this.filteredConversations = [];
                    
                    // Dispatch event for other components
                    window.dispatchEvent(new CustomEvent('conversations-cleared'));
                    
                    return { success: true };
                } else {
                    const data = await response.json();
                    return { success: false, error: data.error || 'Failed to clear conversations' };
                }
            } catch (error) {
                console.error('Error clearing conversations:', error);
                return { success: false, error: 'An unexpected error occurred' };
            }
        },
        
        formatDate(dateString) {
            return DateFormatter.formatRelativeTime(dateString);
        },
        
        getTruncatedMessage(message, maxLength = 60) {
            if (!message) return '';
            
            if (message.length <= maxLength) return message;
            
            return message.substring(0, maxLength) + '...';
        }
    };
}
