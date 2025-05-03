/**
 * Date and Time Formatting Utilities
 * Provides enterprise-grade date/time formatting with timezone awareness
 */

const DateFormatter = {
    /**
     * Format a date string to a user-friendly format based on elapsed time
     * Converts UTC dates to local timezone
     * 
     * @param {string} dateString - ISO date string in UTC
     * @param {Object} options - Formatting options
     * @returns {string} Formatted date string
     */
    formatDate(dateString, options = {}) {
        if (!dateString) return options.emptyText || '';
        
        try {
            const date = new Date(dateString);
            
            // Check if date is valid
            if (isNaN(date.getTime())) {
                console.warn(`Invalid date format: ${dateString}`);
                return options.invalidText || 'Invalid date';
            }
            
            const now = new Date();
            const diffMs = now - date;
            const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
            
            // Today - show time in user's local timezone
            if (this.isSameDay(date, now)) {
                return `Today at ${this.formatTime(date, options)}`;
            }
            
            // Yesterday
            const yesterday = new Date(now);
            yesterday.setDate(now.getDate() - 1);
            if (this.isSameDay(date, yesterday)) {
                return `Yesterday at ${this.formatTime(date, options)}`;
            }
            
            // Within last 7 days - show day of week and time
            if (diffDays < 7) {
                return `${date.toLocaleDateString(options.locale, { weekday: 'long' })} at ${this.formatTime(date, options)}`;
            }
            
            // Older than 7 days - show full date
            return date.toLocaleDateString(options.locale, { 
                year: 'numeric', 
                month: options.monthFormat || 'short', 
                day: 'numeric'
            });
        } catch (error) {
            console.error('Error formatting date:', error);
            return options.errorText || dateString;
        }
    },
    
    /**
     * Format time portion of a date in user's local timezone
     * 
     * @param {Date|string} date - Date object or ISO date string
     * @param {Object} options - Formatting options
     * @returns {string} Formatted time string
     */
    formatTime(date, options = {}) {
        if (typeof date === 'string') {
            date = new Date(date);
        }
        
        try {
            return date.toLocaleTimeString(options.locale, { 
                hour: '2-digit', 
                minute: '2-digit',
                hour12: options.hour12 !== false
            });
        } catch (error) {
            console.error('Error formatting time:', error);
            return '';
        }
    },
    
    /**
     * Format a date with time in user's local timezone
     * 
     * @param {string} dateString - ISO date string
     * @param {Object} options - Formatting options
     * @returns {string} Formatted date and time
     */
    formatDateTime(dateString, options = {}) {
        if (!dateString) return options.emptyText || '';
        
        try {
            const date = new Date(dateString);
            
            // Check if date is valid
            if (isNaN(date.getTime())) {
                return options.invalidText || 'Invalid date';
            }
            
            // Format date and time according to locale
            return date.toLocaleString(options.locale, {
                year: 'numeric',
                month: options.monthFormat || 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                hour12: options.hour12 !== false
            });
        } catch (error) {
            console.error('Error formatting date and time:', error);
            return options.errorText || dateString;
        }
    },
    
    /**
     * Check if two dates are the same calendar day
     * 
     * @param {Date} date1 - First date
     * @param {Date} date2 - Second date
     * @returns {boolean} True if same day
     */
    isSameDay(date1, date2) {
        return date1.getDate() === date2.getDate() &&
               date1.getMonth() === date2.getMonth() &&
               date1.getFullYear() === date2.getFullYear();
    }
};

// Add to window object for global access if needed
window.DateFormatter = DateFormatter;
