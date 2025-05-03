function documentManager() {
    return {
        isAuthenticated: false,
        isCheckingAuth: true,
        documents: [],
        filteredDocuments: [],
        isLoading: true,
        searchQuery: '',
        sortBy: 'recent',  // 'recent', 'alphabetical', 'type'
        viewMode: 'list',  // 'list', 'grid'
        
        // UI state
        selectedDocument: null,
        showUploadModal: false,
        showViewerModal: false,
        showDeleteModal: false,
        documentToDelete: null,
        isUploading: false,
        documentError: null,
        dragOver: false,
        selectedFile: null,
        viewerContent: '',
        
        // Conversation mapping for document context
        conversations: {},
        
        async initialize() {
            await this.checkAuthStatus();
            if (this.isAuthenticated) {
                await this.loadDocuments();
                await this.loadConversations();
                
                // Check URL parameters
                const urlParams = new URLSearchParams(window.location.search);
                const view = urlParams.get('view');
                if (view && ['list', 'grid'].includes(view)) {
                    this.viewMode = view;
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
        
        async loadDocuments() {
            this.isLoading = true;
            
            try {
                const response = await fetch('/documents', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.documents = data.documents || [];
                    this.filterAndSortDocuments();
                } else {
                    console.error('Failed to load documents');
                    dispatchNotification('Failed to load documents', 'error');
                }
            } catch (error) {
                console.error('Error loading documents:', error);
                dispatchNotification('Error loading documents', 'error');
            } finally {
                this.isLoading = false;
            }
        },
        
        async loadConversations() {
            try {
                const response = await fetch('/conversations', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    const conversations = data.conversations || [];
                    
                    // Create a mapping of conversation IDs to names
                    this.conversations = conversations.reduce((map, conversation) => {
                        map[conversation.conversation_id] = conversation.conversation_name || 'Untitled Conversation';
                        return map;
                    }, {});
                }
            } catch (error) {
                console.error('Error loading conversations:', error);
            }
        },
        
        filterAndSortDocuments() {
            // Filter documents based on search query
            if (this.searchQuery.trim() !== '') {
                const query = this.searchQuery.toLowerCase();
                this.filteredDocuments = this.documents.filter(
                    doc => doc.name.toLowerCase().includes(query)
                );
            } else {
                this.filteredDocuments = [...this.documents];
            }
            
            // Sort documents
            this.sortDocuments();
        },
        
        sortDocuments() {
            switch (this.sortBy) {
                case 'recent':
                    this.filteredDocuments.sort((a, b) => 
                        new Date(b.created_at) - new Date(a.created_at)
                    );
                    break;
                    
                case 'alphabetical':
                    this.filteredDocuments.sort((a, b) => 
                        a.name.localeCompare(b.name)
                    );
                    break;
                    
                case 'type':
                    this.filteredDocuments.sort((a, b) => {
                        const typeA = this.getFileType(a.name).toLowerCase();
                        const typeB = this.getFileType(b.name).toLowerCase();
                        return typeA.localeCompare(typeB) || a.name.localeCompare(b.name);
                    });
                    break;
            }
        },
        
        searchDocuments() {
            this.filterAndSortDocuments();
        },
        
        changeSortOrder(order) {
            this.sortBy = order;
            this.filterAndSortDocuments();
        },
        
        getFileType(filename) {
            const extension = filename.split('.').pop().toLowerCase();
            
            const types = {
                'pdf': 'PDF',
                'txt': 'Text',
                'docx': 'Word',
                'doc': 'Word',
                'md': 'Markdown',
                'jpg': 'Image',
                'jpeg': 'Image',
                'png': 'Image',
                'csv': 'CSV',
                'xls': 'Excel',
                'xlsx': 'Excel'
            };
            
            return types[extension] || 'Unknown';
        },
        
        getFileIcon(filename) {
            const extension = filename.split('.').pop().toLowerCase();
            
            const icons = {
                'pdf': 'fa-file-pdf',
                'txt': 'fa-file-alt',
                'docx': 'fa-file-word',
                'doc': 'fa-file-word',
                'md': 'fa-file-alt',
                'jpg': 'fa-file-image',
                'jpeg': 'fa-file-image',
                'png': 'fa-file-image',
                'csv': 'fa-file-csv',
                'xls': 'fa-file-excel',
                'xlsx': 'fa-file-excel'
            };
            
            return `fas ${icons[extension] || 'fa-file'}`;
        },
        
        getFileTypeBadgeClass(filename) {
            const type = this.getFileType(filename);
            
            const classes = {
                'PDF': 'bg-red-100 text-red-800',
                'Text': 'bg-blue-100 text-blue-800',
                'Word': 'bg-blue-100 text-blue-800',
                'Markdown': 'bg-purple-100 text-purple-800',
                'Image': 'bg-green-100 text-green-800',
                'CSV': 'bg-yellow-100 text-yellow-800',
                'Excel': 'bg-green-100 text-green-800'
            };
            
            return classes[type] || 'bg-secondary-100 text-secondary-800';
        },
        
        getConversationName(conversationId) {
            return this.conversations[conversationId] || null;
        },
        
        handleFileSelect(event) {
            const file = event.target.files[0];
            if (file) {
                this.validateAndSetFile(file);
            }
        },
        
        handleFileDrop(event) {
            this.dragOver = false;
            const file = event.dataTransfer.files[0];
            if (file) {
                this.validateAndSetFile(file);
            }
        },
        
        validateAndSetFile(file) {
            // Check file size (max 10MB)
            const maxSize = 10 * 1024 * 1024; // 10MB
            if (file.size > maxSize) {
                this.documentError = 'File size exceeds 10MB limit';
                return;
            }
            
            // Check file type
            const validTypes = [
                'application/pdf',
                'text/plain',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/msword',
                'text/markdown',
                'image/jpeg',
                'image/png',
                'text/csv',
                'application/vnd.ms-excel',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            ];
            
            if (!validTypes.includes(file.type)) {
                this.documentError = 'Unsupported file type';
                return;
            }
            
            // Clear any previous errors
            this.documentError = null;
            this.selectedFile = file;
        },
        
        async uploadDocument() {
            if (!this.selectedFile) return;
            
            this.isUploading = true;
            this.documentError = null;
            
            try {
                const formData = new FormData();
                formData.append('file', this.selectedFile);
                
                const response = await fetch('/upload-document', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                    },
                    body: formData
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Add the new document to our list
                    this.documents.unshift(data.document);
                    this.filterAndSortDocuments();
                    
                    // Reset the upload form
                    this.selectedFile = null;
                    this.showUploadModal = false;
                    
                    dispatchNotification('Document uploaded successfully', 'success');
                } else {
                    this.documentError = data.error || 'Failed to upload document';
                }
            } catch (error) {
                console.error('Error uploading document:', error);
                this.documentError = 'An unexpected error occurred during upload';
            } finally {
                this.isUploading = false;
            }
        },
        
        async viewDocument(documentId) {
            try {
                const response = await fetch(`/document/${documentId}`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.selectedDocument = data.document;
                    this.viewerContent = data.content || 'No preview available for this document type';
                    this.showViewerModal = true;
                } else {
                    const errorData = await response.json();
                    dispatchNotification(errorData.error || 'Failed to load document', 'error');
                }
            } catch (error) {
                console.error('Error viewing document:', error);
                dispatchNotification('An error occurred while loading the document', 'error');
            }
        },
        
        async downloadDocument(documentId, filename) {
            try {
                const response = await fetch(`/document/${documentId}/download`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                    }
                });
                
                if (response.ok) {
                    // Create a blob and download it
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    a.remove();
                } else {
                    const errorData = await response.json();
                    dispatchNotification(errorData.error || 'Failed to download document', 'error');
                }
            } catch (error) {
                console.error('Error downloading document:', error);
                dispatchNotification('An error occurred while downloading the document', 'error');
            }
        },
        
        confirmDeleteDocument(documentId) {
            this.documentToDelete = documentId;
            this.showDeleteModal = true;
        },
        
        async deleteDocument() {
            if (!this.documentToDelete) return;
            
            try {
                const response = await fetch(`/document/${this.documentToDelete}`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                    }
                });
                
                if (response.ok) {
                    // Remove document from our list
                    this.documents = this.documents.filter(doc => doc.doc_id !== this.documentToDelete);
                    this.filterAndSortDocuments();
                    
                    dispatchNotification('Document deleted successfully', 'success');
                } else {
                    const errorData = await response.json();
                    dispatchNotification(errorData.error || 'Failed to delete document', 'error');
                }
            } catch (error) {
                console.error('Error deleting document:', error);
                dispatchNotification('An error occurred while deleting the document', 'error');
            } finally {
                this.showDeleteModal = false;
                this.documentToDelete = null;
            }
        },
        
        formatDate(dateString) {
            return DateFormatter.formatRelativeTime(dateString);
        },
        
        formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
    };
}
