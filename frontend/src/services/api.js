import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';
const TAB_ID = sessionStorage.getItem('tab_id') || crypto.randomUUID();
sessionStorage.setItem('tab_id', TAB_ID);
const getKey = (key) => `${TAB_ID}_${key}`;
// Add connection check utility
let isServerConnected = false;

let keyManager = null;

export const checkServerConnection = async () => {
  try {
    console.log('Checking server connection to:', `${API_BASE_URL}/api/debug`);
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`${API_BASE_URL}/api/debug`, {
      method: 'GET',
      signal: controller.signal,
      mode: 'cors',
      credentials: 'omit'
    });
    
    clearTimeout(timeoutId);
    
    if (response.ok) {
      console.log('Server is connected and responding');
      isServerConnected = true;
      return true;
    } else {
      console.log('Server responded with error status:', response.status);
      isServerConnected = false;
      return false;
    }
  } catch (error) {
    console.error('Server connection check failed:', error);
    
    if (error.name === 'AbortError') {
      console.error('Connection timeout - server might be slow or unavailable');
    } else if (error.name === 'TypeError') {
      console.error('Network error - check if backend is running on port 8000');
    }
    
    isServerConnected = false;
    return false;
  }
};

export const initializeE2EE = async () => {
  try {
    console.log('Initializing E2EE system...');
    const manager = await getKeyManager();
    await manager.initialize();
    console.log('E2EE system initialized successfully');
    return true;
  } catch (error) {
    console.error('E2EE initialization failed:', error);
    return false;
  }
};

export const getKeyManager = async () => {
  if (!keyManager) {
    try {
      const KeyManagerModule = await import('./keyManager.js');
      const KeyManager = KeyManagerModule.default;
      keyManager = new KeyManager();
      console.log('KeyManager loaded successfully');
    } catch (error) {
      console.error('Failed to load KeyManager:', error);
      throw error;
    }
  }
  return keyManager;
};

export const apiCall = async (endpoint, options = {}) => {
  try {
    // Get token from multiple sources with fallbacks
    const getToken = () => {
      return (
        sessionStorage.getItem('token') ||
        localStorage.getItem('token') ||
        localStorage.getItem('authToken') ||
        null
      );
    };

    const token = getToken();
    
    console.log('API Call Token Check:', {
      endpoint,
      tokenExists: !!token,
      tokenLength: token ? token.length : 0
    });

    if (!token) {
      throw new Error('Authentication token missing. Please log in again.');
    }

    const defaultHeaders = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    };

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      headers: { ...defaultHeaders, ...options.headers },
      ...options,
    });

    if (response.status === 401) {
      // Token is invalid, clear auth data
      console.log('Token invalid, clearing auth data');
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      sessionStorage.removeItem('token');
      sessionStorage.removeItem('user');
      throw new Error('Session expired. Please log in again.');
    }

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    console.error(`API call to ${endpoint} failed:`, error);
    throw error;
  }
};

// login: async (username, password) => {
    //     try {
    //     const response = await fetch(`${API_BASE_URL}/api/login`, {
    //         method: 'POST',
    //         headers: {
    //         'Content-Type': 'application/json',
    //         },
    //         body: JSON.stringify({ username, password }),
    //     });
        
    //         if (!response.ok) {
    //             // Store token for later authenticated requests
    //             localStorage.setItem('token', data.token);

    //             // Also store basic user info if needed
    //             setUser(data.user);
    //             const errorData = await response.json().catch(() => ({}));
    //             throw new Error(errorData.error || 'Login failed');
    //         }
        
    //     const result = await response.json();
        
    //     // Initialize E2EE after successful login
    //     if (result.success && result.token) {
    //         setTimeout(() => {
    //         initializeE2EE().then(success => {
    //             if (success) {
    //             console.log('E2EE ready for secure messaging');
    //             }
    //         });
    //         }, 1000);
    //     }
        
    //     return result;
    //     } catch (error) {
    //     if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
    //         throw new Error('Cannot connect to server. Please make sure the backend is running on port 8000.');
    //     }
    //     throw error;
    //     }
    // },

export const authAPI = {    
    login: async (username, password) => {
        try {
            const response = await fetch(`${API_BASE_URL}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            });

            if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Login failed');
            }

            const data = await response.json();

            // Store token and user info
            if (data.token) localStorage.setItem(getKey('token'), data.token);
            
            if (data.user) {
                // localStorage.setItem('user', JSON.stringify(data.user));
                localStorage.setItem(getKey('user'), JSON.stringify(data.user));
            }

            // Initialize E2EE after successful login
            if (data.success && data.token) {
            setTimeout(() => {
                initializeE2EE().then(success => {
                if (success) console.log('E2EE ready for secure messaging');
                });
            }, 1000);
            }

            return data;
        } catch (error) {
            if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
            throw new Error('Cannot connect to server. Please make sure the backend is running on port 8000.');
            }
            throw error;
        }
    },
    
    register: async (userData) => {
        try {
        console.log('Register API called with:', userData);
        const response = await fetch(`${API_BASE_URL}/api/register`, {
            method: 'POST',
            headers: {
            'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData),
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Register error response:', errorText);
            throw new Error(errorText || 'Registration failed');
        }
        
        const result = await response.json();
        
        // Initialize E2EE after successful registration
        if (result.success && result.token) {
            setTimeout(() => {
            initializeE2EE().then(success => {
                if (success) {
                console.log('E2EE ready for secure messaging');
                }
            });
            }, 1000);
        }
        
        return result;
        } catch (error) {
        if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
            throw new Error('Cannot connect to server. Please make sure the backend is running on port 8000.');
        }
        throw error;
        }
    },

    verifyToken: async (token) => {
        if (!token) {
        console.warn('No token provided for verification');
        return false;
        }
        try {
        const response = await fetch(`${API_BASE_URL}/api/verify-token`, {
            method: 'GET',
            headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            },
        });

        if (response.ok) {
            const data = await response.json();
            return data.valid;
        }
        
        if (response.status === 404) {
            console.warn('verify-token endpoint not found, using local verification');
            return verifyTokenLocally(token);
        }  
        
        console.warn(`Token verification failed with status ${response.status}, trying local verification`);
        return verifyTokenLocally(token);
        } catch (error) {
        console.error('Token verification failed:', error);
        return verifyTokenLocally(token);
        }
    },

    // UPDATED: E2EE KEY EXCHANGE
    exchangePublicKey: async (publicKey, token) => {
        try {
        console.log('Exchanging public key with server...');
        const response = await fetch(`${API_BASE_URL}/api/keys/register`, { // Changed endpoint
            method: 'POST',
            headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ public_key: publicKey })
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Key exchange failed:', errorText);
            throw new Error(`Key exchange failed: ${response.status}`);
        }

        const result = await response.json();
        console.log('Public key registered successfully');
        return result;
        } catch (error) {
        console.error('Key exchange API error:', error);
        throw error;
        }
    },

    // UPDATED: GET PUBLIC KEY
    getPublicKey: async (userId, token) => {
        try {
        console.log(`Getting public key for user: ${userId}`);
        const response = await fetch(`${API_BASE_URL}/api/keys/${userId}`, {
            method: 'GET',
            headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            },
        });

        if (!response.ok) {
            if (response.status === 404) {
            console.warn(`Public key not found for user: ${userId}`);
            return null;
            }
            throw new Error(`Failed to get public key: ${response.status}`);
        }

        const result = await response.json();
        console.log('Public key retrieved successfully');
        return result.public_key; // Return just the public key string
        } catch (error) {
        console.error('Get public key API error:', error);
        return null;
        }
    }
};

export const stegoAPI = {
  encode: async (file, message, fileType) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('message', message);
    formData.append('fileType', fileType);

    const response = await fetch(`${API_BASE_URL}/api/encode`, {
      method: 'POST',
      body: formData,
    });
    
    if (!response.ok) {
      throw new Error('Encoding failed');
    }
    
    return response.blob();
  },

  decode: async (file, fileType) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('fileType', fileType);

    const response = await fetch(`${API_BASE_URL}/api/decode`, {
      method: 'POST',
      body: formData,
    });
    
    if (!response.ok) {
      throw new Error('Decoding failed');
    }
    
    return response.json();
  },
};

export const chatAPI = {
  getUsers: async () => {
    const response = await fetch(`${API_BASE_URL}/api/users`);
    
    if (!response.ok) {
      throw new Error('Failed to fetch users');
    }
    
    return response.json();
  },

  getMessages: async (userId) => {
    try {
      console.log(`📨 Fetching messages for user: ${userId}`);
      const response = await fetch(`${API_BASE_URL}/api/messages/${userId}`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch messages');
      }
      
      const data = await response.json();
      console.log(`Retrieved ${data.messages?.length || 0} messages`);
      
      // ADD: Decrypt messages if they are encrypted
      if (data.messages && data.messages.length > 0) {
        const decryptedMessages = await Promise.all(
          data.messages.map(async (message) => {
            if (message.encrypted_content) {
              try {
                const decryptedText = await keyManager.decryptMessage(
                  message.encrypted_content,
                  message.sender_id
                );
                return { ...message, decryptedText };
              } catch (error) {
                console.error('Failed to decrypt message:', error);
                return { ...message, decryptedText: 'Unable to decrypt message' };
              }
            }
            return message;
          })
        );
        return { ...data, messages: decryptedMessages };
      }
      
      return data;
    } catch (error) {
      console.error('Get messages error:', error);
      throw error;
    }
  },

  // UPDATED: Send encrypted message using KeyManager
  sendMessage: async (messageData) => {
    try {
      console.log('Sending message...', {
        receiver: messageData.receiver_id,
        hasEncryptedContent: !!messageData.encrypted_content,
        messageType: messageData.encrypted_content ? 'ENCRYPTED' : 'PLAINTEXT'
      });

      const response = await fetch(`${API_BASE_URL}/api/send-message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(messageData),
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('Send message failed:', errorText);
        throw new Error('Failed to send message');
      }
      
      const result = await response.json();
      console.log('Message sent successfully');
      return result;
    } catch (error) {
      console.error('Send message API error:', error);
      throw error;
    }
  },

  // NEW: Send encrypted message with automatic encryption
  sendEncryptedMessage: async (receiverId, plaintextMessage) => {
    try {
      console.log('Preparing encrypted message for:', receiverId);
      
      // Encrypt the message using KeyManager
      const encryptedContent = await keyManager.encryptMessage(plaintextMessage, receiverId);
      
      // Get current user ID from token
      const token = localStorage.getItem('token') || sessionStorage.getItem('token');
      let senderId = null;
      
      if (token) {
        try {
          const payload = JSON.parse(atob(token.split('.')[1]));
          senderId = payload._id;
        } catch (e) {
          console.error('Failed to extract sender ID from token:', e);
        }
      }

      // Prepare encrypted message payload
      const encryptedMessage = {
        sender_id: senderId,
        receiver_id: receiverId,
        encrypted_content: encryptedContent,
        timestamp: new Date().toISOString()
      };

      console.log('Sending encrypted message to server...');
      return await chatAPI.sendMessage(encryptedMessage);
    } catch (error) {
      console.error('Failed to send encrypted message:', error);
      throw new Error(`Encryption failed: ${error.message}`);
    }
  },

  // NEW: Simplified message sending that automatically encrypts
  sendMessageAutoEncrypt: async (receiverId, messageText) => {
    try {
      // Always encrypt messages
      return await chatAPI.sendEncryptedMessage(receiverId, messageText);
    } catch (error) {
      console.error('Auto-encrypt message failed:', error);
      throw error;
    }
},
  
  deleteMessage: async (messageId) => {
    try {
      console.log(`Deleting message: ${messageId}`);
      
      // Get token from multiple sources
      const getToken = () => {
        return (
          sessionStorage.getItem('token') ||
          localStorage.getItem('token') ||
          localStorage.getItem('authToken') ||
          null
        );
      };

      const token = getToken();
      
      if (!token) {
        throw new Error('Authentication token missing. Please log in again.');
      }

      const response = await fetch(`${API_BASE_URL}/api/messages/${messageId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('Delete message failed:', errorText);
        
        if (response.status === 401) {
          // Token is invalid, clear auth data
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          sessionStorage.removeItem('token');
          sessionStorage.removeItem('user');
          throw new Error('Session expired. Please log in again.');
        } else if (response.status === 403) {
          throw new Error('You are not authorized to delete this message');
        } else if (response.status === 404) {
          throw new Error('Message not found or already deleted');
        } else {
          throw new Error(`Delete failed: ${response.status} - ${errorText}`);
        }
      }

      const result = await response.json();
      console.log('Message deleted successfully:', result);
      return result;
      
    } catch (error) {
      console.error('Delete message API error:', error);
      throw error;
    }
  },
};

export const searchUsers = async (searchTerm) => {
  try {
    // Get token from multiple sources
    const getToken = () => {
      return (
        sessionStorage.getItem('token') ||
        localStorage.getItem('token') ||
        null
      );
    };

    const token = getToken();
    
    console.log('Search Users - Token Check:', {
      tokenExists: !!token,
      searchTerm
    });

    if (!token) {
      return {
        success: false,
        message: 'Authentication token missing. Please log in again.'
      };
    }

    console.log(`Searching users with term: ${searchTerm}`);
    
    const response = await axios.get(`${API_BASE_URL}/api/users/search`, {
      params: { q: searchTerm },
      headers: {
        Authorization: `Bearer ${token}`
      },
      timeout: 5000
    });
    
    console.log('Search response:', response.data);
    return response.data;
  } catch (error) {
    console.error('Search users error:', error);
    
    if (error.code === 'ECONNREFUSED' || error.message.includes('Network Error')) {
      return {
        success: false,
        message: 'Cannot connect to server. Please make sure the backend is running on port 8000.'
      };
    } else if (error.response?.status === 401) {
      // Token is invalid, clear auth data
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      sessionStorage.removeItem('token');
      sessionStorage.removeItem('user');
      return {
        success: false,
        message: 'Session expired. Please log in again.'
      };
    } else if (error.response) {
      return {
        success: false,
        message: error.response.data?.message || `Server error: ${error.response.status}`
      };
    } else if (error.request) {
      return {
        success: false,
        message: 'Network error: Could not connect to server'
      };
    } else {
      return {
        success: false,
        message: error.message || 'Failed to search users'
      };
    }
  }
};

export const verifyTokenLocally = (token) => {
  try {
    if (!token) return false;
    
    // Simple JWT structure check (basic validation)
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    
    // Try to decode the payload
    try {
      const payload = JSON.parse(atob(parts[1]));
      
      // Check expiration
      if (payload.exp && Date.now() >= payload.exp * 1000) {
        console.log('Token expired');
        return false;
      }
      
      return true;
    } catch (e) {
      console.log('Invalid token payload');
      return false;
    }
  } catch (error) {
    console.error('Local token verification error:', error);
    return false;
  }
};

export const serverStatus = {
  isConnected: false,
  
  checkStatus: async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/debug`, {
        method: 'GET',
        signal: AbortSignal.timeout(2000)
      });
      serverStatus.isConnected = response.ok;
      return serverStatus.isConnected;
    } catch (error) {
      serverStatus.isConnected = false;
      return false;
    }
  },
  
  getStatus: () => serverStatus.isConnected
};

export const e2eeAPI = {
  // Initialize E2EE system
  initialize: initializeE2EE,
  
  // Get key manager instance
  getKeyManager: getKeyManager,
  
  // Check if E2EE is ready
  isReady: async () => {
    const manager = await getKeyManager();
    return manager.isReady();
  },
  
  // Get current user's public key
  getMyPublicKey: async () => {
    const manager = await getKeyManager();
    return manager.getMyPublicKey();
  },
  
  // ADDED BACK: Register public key with server
  registerPublicKey: async (token) => {
    try {
      console.log('Registering public key with server...');
      const manager = await getKeyManager();
      const publicKey = manager.getMyPublicKey();
      
      if (!publicKey) {
        throw new Error('No public key available');
      }
      
      // Use the authAPI to register the public key
      const result = await authAPI.exchangePublicKey(publicKey, token);
      console.log('Public key registered successfully');
      return result;
      
    } catch (error) {
      console.error('Public key registration failed:', error);
      throw error;
    }
  },
  
  // Initialize secure conversation with another user
  initializeConversation: async (targetUserId, token) => {
    try {
      console.log(`Initializing secure conversation with: ${targetUserId}`);
      const manager = await getKeyManager();
      return await manager.establishSecureChannel(targetUserId);
    } catch (error) {
      console.error('Secure conversation initialization failed:', error);
      throw error;
    }
  },
  
  // ADDED: Encrypt message for a user
  encryptMessage: async (message, targetUserId) => {
    try {
      const manager = await getKeyManager();
      return await manager.encryptMessage(message, targetUserId);
    } catch (error) {
      console.error('Message encryption failed:', error);
      throw error;
    }
  },
  
  // ADDED: Decrypt message from a user
  decryptMessage: async (encryptedData, senderUserId) => {
    try {
      const manager = await getKeyManager();
      return await manager.decryptMessage(encryptedData, senderUserId);
    } catch (error) {
      console.error('Message decryption failed:', error);
      throw error;
    }
  },
  
  // ADDED: Clear all keys (useful for logout)
  clearKeys: async () => {
    try {
      const manager = await getKeyManager();
      manager.clearKeys();
      console.log('All E2EE keys cleared');
    } catch (error) {
      console.error('Failed to clear keys:', error);
    }
  }
};

export const deleteMessageAPI = async (messageId) => {
  try {
    console.log('API: Starting message deletion process...');
    
    // Use the chatAPI delete function
    const result = await chatAPI.deleteMessage(messageId);
    
    console.log('API: Message deletion completed successfully');
    return {
      success: true,
      data: result,
      message: 'Message deleted successfully'
    };
    
  } catch (error) {
    console.error('API: Message deletion failed:', error);
    
    // Return structured error response
    return {
      success: false,
      error: error.message || 'Failed to delete message',
      code: error.name || 'DELETE_ERROR'
    };
  }
};

export const deleteMessagesBulk = async (messageIds) => {
  try {
    console.log(`API: Bulk deleting ${messageIds.length} messages...`);
    
    const results = await Promise.allSettled(
      messageIds.map(id => chatAPI.deleteMessage(id))
    );
    
    const successfulDeletes = results.filter(result => result.status === 'fulfilled').length;
    const failedDeletes = results.filter(result => result.status === 'rejected').length;
    
    console.log(`API: Bulk delete completed - ${successfulDeletes} successful, ${failedDeletes} failed`);
    
    return {
      success: true,
      total: messageIds.length,
      successful: successfulDeletes,
      failed: failedDeletes,
      results: results.map((result, index) => ({
        messageId: messageIds[index],
        status: result.status,
        ...(result.status === 'fulfilled' ? { data: result.value } : { error: result.reason.message })
      }))
    };
    
  } catch (error) {
    console.error('API: Bulk delete failed:', error);
    return {
      success: false,
      error: error.message || 'Bulk delete failed',
      total: messageIds.length,
      successful: 0,
      failed: messageIds.length
    };
  }
};

export const canDeleteMessage = (message, currentUserId) => {
  if (!message || !currentUserId) return false;
  
  const senderId = message.sender_id || message.senderId;
  const receiverId = message.receiver_id || message.receiverId;
  
  // Normalize IDs for comparison
  const normalizeId = (id) => {
    if (!id) return null;
    if (typeof id === 'string') return id;
    if (id.toString) return id.toString();
    return String(id);
  };
  
  const normalizedCurrent = normalizeId(currentUserId);
  const normalizedSender = normalizeId(senderId);
  const normalizedReceiver = normalizeId(receiverId);
  
  // User can delete if they are the sender OR receiver
  return normalizedCurrent === normalizedSender || normalizedCurrent === normalizedReceiver;
};

export default {
  authAPI,
  chatAPI,
  stegoAPI,
  e2eeAPI,
  searchUsers,
  checkServerConnection,
  serverStatus,
  initializeE2EE,
  getKeyManager,
  deleteMessageAPI,
  deleteMessagesBulk,
  canDeleteMessage
};