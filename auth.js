// Enhanced Local Storage Management for User and Admin Data

// Admin credentials
const ADMIN_EMAIL = 'devcore.communicate@gmail.com';
const ADMIN_PASSWORD = 'dev_core_25.6.2025';

// Storage Keys
const STORAGE_KEYS = {
    AUTH_TOKEN: 'authToken',
    USER_DATA: 'user',
    USERS_LIST: 'registeredUsers',
    ADMIN_DATA: 'admin',
    REMEMBER_ME: 'rememberMe',
    SESSION_EXPIRY: 'sessionExpiry',
    LOGS: 'authLogs'
};

// Enhanced Storage Management
const storageManager = {
    // User Data Management
    saveUser: (userData) => {
        try {
            // Save current user session
            localStorage.setItem(STORAGE_KEYS.USER_DATA, JSON.stringify(userData));
            
            // Save to users list if not admin
            if (userData.email !== ADMIN_EMAIL) {
                const users = storageManager.getAllUsers();
                const existingUserIndex = users.findIndex(u => u.email === userData.email);
                
                if (existingUserIndex !== -1) {
                    // Update existing user
                    users[existingUserIndex] = {
                        ...users[existingUserIndex],
                        ...userData,
                        lastLogin: new Date().toISOString(),
                        updatedAt: new Date().toISOString()
                    };
                } else {
                    // Add new user
                    const newUser = {
                        ...userData,
                        id: Date.now().toString(),
                        createdAt: new Date().toISOString(),
                        lastLogin: new Date().toISOString(),
                        isActive: true
                    };
                    users.push(newUser);
                }
                
                localStorage.setItem(STORAGE_KEYS.USERS_LIST, JSON.stringify(users));
            }
            
            return true;
        } catch (error) {
            console.error('Error saving user data:', error);
            return false;
        }
    },

    // Admin Data Management
    saveAdmin: (adminData) => {
        try {
            const adminInfo = {
                ...adminData,
                isAdmin: true,
                lastAccess: new Date().toISOString(),
                permissions: ['all']
            };
            
            localStorage.setItem(STORAGE_KEYS.ADMIN_DATA, JSON.stringify(adminInfo));
            return true;
        } catch (error) {
            console.error('Error saving admin data:', error);
            return false;
        }
    },

    // Get current user/admin
    getCurrentUser: () => {
        try {
            const userStr = localStorage.getItem(STORAGE_KEYS.USER_DATA);
            if (userStr) {
                return JSON.parse(userStr);
            }
            
            // Check if admin is logged in
            const adminStr = localStorage.getItem(STORAGE_KEYS.ADMIN_DATA);
            if (adminStr) {
                return JSON.parse(adminStr);
            }
            
            return null;
        } catch (error) {
            console.error('Error getting current user:', error);
            return null;
        }
    },

    // Get all registered users (excluding admin)
    getAllUsers: () => {
        try {
            const usersStr = localStorage.getItem(STORAGE_KEYS.USERS_LIST);
            return usersStr ? JSON.parse(usersStr) : [];
        } catch (error) {
            console.error('Error getting all users:', error);
            return [];
        }
    },

    // Get user by ID or email
    getUser: (identifier) => {
        const users = storageManager.getAllUsers();
        return users.find(user => 
            user.id === identifier || 
            user.email === identifier ||
            user.username === identifier
        );
    },

    // Update user data
    updateUser: (identifier, updates) => {
        try {
            const users = storageManager.getAllUsers();
            const userIndex = users.findIndex(user => 
                user.id === identifier || 
                user.email === identifier
            );
            
            if (userIndex !== -1) {
                users[userIndex] = {
                    ...users[userIndex],
                    ...updates,
                    updatedAt: new Date().toISOString()
                };
                
                localStorage.setItem(STORAGE_KEYS.USERS_LIST, JSON.stringify(users));
                
                // Update current session if it's the same user
                const currentUser = storageManager.getCurrentUser();
                if (currentUser && (currentUser.email === identifier || currentUser.id === identifier)) {
                    localStorage.setItem(STORAGE_KEYS.USER_DATA, JSON.stringify(users[userIndex]));
                }
                
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('Error updating user:', error);
            return false;
        }
    },

    // Delete user
    deleteUser: (identifier) => {
        try {
            let users = storageManager.getAllUsers();
            const initialLength = users.length;
            
            users = users.filter(user => 
                user.id !== identifier && 
                user.email !== identifier
            );
            
            if (users.length < initialLength) {
                localStorage.setItem(STORAGE_KEYS.USERS_LIST, JSON.stringify(users));
                
                // Clear current session if deleted user is logged in
                const currentUser = storageManager.getCurrentUser();
                if (currentUser && (currentUser.email === identifier || currentUser.id === identifier)) {
                    storageManager.clearSession();
                }
                
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('Error deleting user:', error);
            return false;
        }
    },

    // Session Management
    setSession: (token, userData) => {
        try {
            // Save token
            localStorage.setItem(STORAGE_KEYS.AUTH_TOKEN, token);
            
            // Set session expiry (24 hours)
            const expiry = new Date();
            expiry.setHours(expiry.getHours() + 24);
            localStorage.setItem(STORAGE_KEYS.SESSION_EXPIRY, expiry.toISOString());
            
            // Save user data
            if (userData.email === ADMIN_EMAIL) {
                storageManager.saveAdmin(userData);
            } else {
                storageManager.saveUser(userData);
            }
            
            // Log the login
            storageManager.logActivity(userData.email, 'login', 'User logged in successfully');
            
            return true;
        } catch (error) {
            console.error('Error setting session:', error);
            return false;
        }
    },

    // Check session validity
    isSessionValid: () => {
        const token = localStorage.getItem(STORAGE_KEYS.AUTH_TOKEN);
        const expiryStr = localStorage.getItem(STORAGE_KEYS.SESSION_EXPIRY);
        
        if (!token || !expiryStr) return false;
        
        const expiry = new Date(expiryStr);
        const now = new Date();
        
        return now < expiry;
    },

    // Clear session
    clearSession: () => {
        const currentUser = storageManager.getCurrentUser();
        if (currentUser) {
            storageManager.logActivity(currentUser.email, 'logout', 'User logged out');
        }
        
        localStorage.removeItem(STORAGE_KEYS.AUTH_TOKEN);
        localStorage.removeItem(STORAGE_KEYS.USER_DATA);
        localStorage.removeItem(STORAGE_KEYS.ADMIN_DATA);
        localStorage.removeItem(STORAGE_KEYS.SESSION_EXPIRY);
        localStorage.removeItem(STORAGE_KEYS.REMEMBER_ME);
    },

    // Activity Logging
    logActivity: (userEmail, action, details) => {
        try {
            const logsStr = localStorage.getItem(STORAGE_KEYS.LOGS);
            const logs = logsStr ? JSON.parse(logsStr) : [];
            
            const logEntry = {
                id: Date.now().toString(),
                userEmail,
                action,
                details,
                timestamp: new Date().toISOString(),
                ip: 'N/A' // Can be enhanced with actual IP if available
            };
            
            logs.unshift(logEntry); // Add to beginning
            
            // Keep only last 100 logs
            if (logs.length > 100) {
                logs.pop();
            }
            
            localStorage.setItem(STORAGE_KEYS.LOGS, JSON.stringify(logs));
        } catch (error) {
            console.error('Error logging activity:', error);
        }
    },

    // Get activity logs
    getActivityLogs: (limit = 50) => {
        try {
            const logsStr = localStorage.getItem(STORAGE_KEYS.LOGS);
            const logs = logsStr ? JSON.parse(logsStr) : [];
            return logs.slice(0, limit);
        } catch (error) {
            console.error('Error getting activity logs:', error);
            return [];
        }
    },

    // Statistics
    getStats: () => {
        const users = storageManager.getAllUsers();
        const logs = storageManager.getActivityLogs(1000);
        
        const totalUsers = users.length;
        const activeUsers = users.filter(u => u.isActive !== false).length;
        const today = new Date().toDateString();
        const todayLogins = logs.filter(log => 
            log.action === 'login' && 
            new Date(log.timestamp).toDateString() === today
        ).length;
        
        return {
            totalUsers,
            activeUsers,
            todayLogins,
            lastActivity: logs[0] || null
        };
    },

    // Backup and Restore
    backupData: () => {
        try {
            const data = {
                users: storageManager.getAllUsers(),
                logs: storageManager.getActivityLogs(1000),
                timestamp: new Date().toISOString(),
                version: '1.0'
            };
            
            return JSON.stringify(data);
        } catch (error) {
            console.error('Error backing up data:', error);
            return null;
        }
    },

    // Clear all data (for testing/reset)
    clearAllData: () => {
        Object.values(STORAGE_KEYS).forEach(key => {
            localStorage.removeItem(key);
        });
    }
};

// Enhanced Utility Functions
const utils = {
    // Check if user is logged in with valid session
    isLoggedIn: () => {
        return storageManager.isSessionValid();
    },

    // Get current user
    getCurrentUser: () => {
        return storageManager.getCurrentUser();
    },

    // Check if current user is admin
    isAdmin: () => {
        const user = storageManager.getCurrentUser();
        return user && user.email === ADMIN_EMAIL;
    },

    // Set user session
    setSession: (token, user) => {
        return storageManager.setSession(token, user);
    },

    // Clear session
    clearSession: () => {
        storageManager.clearSession();
    },

    // Redirect based on user role
    redirectUser: (user) => {
        if (user.email === ADMIN_EMAIL) {
            storageManager.saveAdmin(user);
            window.location.href = 'admin_panel.html';
        } else {
            window.location.href = 'dashboard.html';
        }
    },

    // Show message
    showMessage: (elementId, message, type) => {
        const messageEl = document.getElementById(elementId);
        if (messageEl) {
            messageEl.textContent = message;
            messageEl.className = `form-message ${type}`;
            messageEl.style.display = 'block';

            if (type === 'success') {
                setTimeout(() => {
                    messageEl.style.display = 'none';
                }, 3000);
            }
        }
    },

    // Hide message
    hideMessage: (elementId) => {
        const messageEl = document.getElementById(elementId);
        if (messageEl) {
            messageEl.style.display = 'none';
        }
    },

    // Admin Functions
    admin: {
        // Get all users
        getAllUsers: () => {
            if (!utils.isAdmin()) {
                console.error('Access denied: Admin privileges required');
                return [];
            }
            return storageManager.getAllUsers();
        },

        // Get user by ID
        getUserById: (userId) => {
            if (!utils.isAdmin()) {
                console.error('Access denied: Admin privileges required');
                return null;
            }
            return storageManager.getUser(userId);
        },

        // Update user
        updateUser: (userId, updates) => {
            if (!utils.isAdmin()) {
                console.error('Access denied: Admin privileges required');
                return false;
            }
            return storageManager.updateUser(userId, updates);
        },

        // Delete user
        deleteUser: (userId) => {
            if (!utils.isAdmin()) {
                console.error('Access denied: Admin privileges required');
                return false;
            }
            return storageManager.deleteUser(userId);
        },

        // Get activity logs
        getLogs: (limit = 50) => {
            if (!utils.isAdmin()) {
                console.error('Access denied: Admin privileges required');
                return [];
            }
            return storageManager.getActivityLogs(limit);
        },

        // Get statistics
        getStats: () => {
            if (!utils.isAdmin()) {
                console.error('Access denied: Admin privileges required');
                return null;
            }
            return storageManager.getStats();
        },

        // Backup data
        backupData: () => {
            if (!utils.isAdmin()) {
                console.error('Access denied: Admin privileges required');
                return null;
            }
            return storageManager.backupData();
        },

        // Restore from backup (for future implementation)
        restoreBackup: (backupData) => {
            if (!utils.isAdmin()) {
                console.error('Access denied: Admin privileges required');
                return false;
            }
            // Implementation would depend on backup format
            console.log('Restore backup functionality to be implemented');
            return false;
        }
    }
};

// Check and validate session on page load
document.addEventListener('DOMContentLoaded', function() {
    // Auto-check session validity
    if (storageManager.isSessionValid()) {
        const user = storageManager.getCurrentUser();
        if (user) {
            console.log(`Session active for user: ${user.email}`);
            
            // Redirect if on login/signup pages
            if (window.location.pathname.includes('login.html') || 
                window.location.pathname.includes('signup.html')) {
                utils.redirectUser(user);
            }
        }
    } else {
        // Clear invalid session
        storageManager.clearSession();
    }
});

// Export for use in other scripts
window.authUtils = utils;
window.storageManager = storageManager;
window.validators = validators;

// Initialize storage with admin user if not exists
function initializeStorage() {
    const users = storageManager.getAllUsers();
    const adminExists = users.some(user => user.email === ADMIN_EMAIL);
    
    if (!adminExists) {
        const adminUser = {
            id: 'admin_001',
            fullname: 'System Administrator',
            username: 'admin',
            email: ADMIN_EMAIL,
            phone: '+1234567890',
            role: 'admin',
            createdAt: new Date().toISOString(),
            lastLogin: null,
            isActive: true
        };
        
        storageManager.saveUser(adminUser);
        console.log('Admin user initialized in storage');
    }
}

// Initialize on load
setTimeout(initializeStorage, 1000);

// Enhanced Logout function with storage cleanup
window.logout = function() {
    storageManager.clearSession();
    window.location.href = 'login.html';
};

// Function to display user profile (for dashboard)
window.displayUserProfile = function() {
    const user = storageManager.getCurrentUser();
    if (!user) return null;
    
    return {
        name: user.fullname || user.username,
        email: user.email,
        role: user.role || 'user',
        lastLogin: user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'First login',
        memberSince: user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'
    };
};