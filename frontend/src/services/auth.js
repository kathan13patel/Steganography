import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import { authAPI } from './api';
import encryptionService from './encryptionService'; 

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  // Each tab gets a unique ID that persists while the tab is open
  const TAB_ID = sessionStorage.getItem('tab_id') || crypto.randomUUID();
  sessionStorage.setItem('tab_id', TAB_ID);

  // Helper function for per-tab keys
  const getKey = (key) => `${TAB_ID}_${key}`;
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const [encryptionStatus, setEncryptionStatus] = useState(null); 
  const isCheckingRef = useRef(false);

  const isAuthenticated = !!token;

  useEffect(() => {
    if (!isCheckingRef.current) {
      checkAuthStatus();
    }
  }, []);

  // Quick token validation without server call
  const validateTokenQuickly = (token) => {
    if (!token) return false;
    
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return false;
      
      const payload = JSON.parse(atob(parts[1]));
      
      // Check expiration
      if (payload.exp && Date.now() >= payload.exp * 1000) {
        return false;
      }
      
      return true;
    } catch (e) {
      return false;
    }
  };

  const checkAuthStatus = async () => {
    if (isCheckingRef.current) return;
    isCheckingRef.current = true;
    
    try {
      console.log('Quick auth status check...');
      
        //   const savedToken = sessionStorage.getItem('token') || localStorage.getItem('token');
        //   const savedUser = sessionStorage.getItem('user') || localStorage.getItem('user');
      
        const savedToken = sessionStorage.getItem(getKey('token')) || localStorage.getItem(getKey('token'));
        const savedUser = sessionStorage.getItem(getKey('user')) || localStorage.getItem(getKey('user'));

      // Quick validation without server call
      if (savedToken && savedUser && validateTokenQuickly(savedToken)) {
        console.log('Token valid locally, setting user immediately');
        const userData = JSON.parse(savedUser);
        setToken(savedToken);
        setUser(userData);
        
        // Initialize encryption in background without blocking
        setTimeout(() => {
          initializeUserEncryption(userData.id).catch(console.error);
        }, 100);
        
      } else {
        console.log('No valid token found');
        clearAuthData();
      }
    } catch (error) {
      console.error('Error in auth check:', error);
      clearAuthData();
    } finally {
      setLoading(false);
      isCheckingRef.current = false;
    }
  };

  // Optimized encryption initialization
  const initializeUserEncryption = async (userId) => {
    try {
      console.log('Initializing E2EE for user:', userId);
      
      // Quick check for existing keys
      if (encryptionService.hasUserKeys(userId)) {
        const status = encryptionService.getEncryptionStatus(userId);
        console.log('User already has encryption keys');
        setEncryptionStatus(status);
        return true;
      }

      // Generate keys with timeout
      const generateKeysWithTimeout = () => {
        return new Promise((resolve, reject) => {
          const timeout = setTimeout(() => {
            reject(new Error('Key generation timeout'));
          }, 5000); // 5 second timeout
          
          encryptionService.generateUserKeys()
            .then(keys => {
              clearTimeout(timeout);
              resolve(keys);
            })
            .catch(error => {
              clearTimeout(timeout);
              reject(error);
            });
        });
      };

      console.log('Generating cryptographic keys...');
      const userKeys = await generateKeysWithTimeout();
      
      // Store keys locally
      encryptionService.storeUserKeys(userId, userKeys);
      
      const status = encryptionService.getEncryptionStatus(userId);
      setEncryptionStatus(status);
      console.log('E2EE initialized');

      // Exchange public key in background (don't wait for it)
      const currentToken = sessionStorage.getItem('token') || localStorage.getItem('token');
      if (currentToken) {
        authAPI.exchangePublicKey({
          public_key: userKeys.keyPair.publicKey,
          target_user_id: 'server',
          key_id: userKeys.keyId,
          is_fallback: userKeys.isFallback || false
        }, currentToken).catch(error => {
          console.warn('Key exchange failed (non-critical):', error);
        });
      }

      return true;
    } catch (error) {
      console.error('E2EE initialization failed:', error);
      setEncryptionStatus({
        hasKeys: false,
        error: error.message,
        webCryptoAvailable: encryptionService.isWebCryptoAvailable()
      });
      return false;
    }
  };

  const clearAuthData = () => {
    console.log('Clearing auth data...');
    
    // Clear encryption keys for current user
    if (user?.id) {
      try {
        localStorage.removeItem(`e2ee_keys_${user.id}`);
        sessionStorage.removeItem(`e2ee_keys_${user.id}`);
      } catch (error) {
        console.error('Failed to clear encryption keys:', error);
      }
    }
    
    // Clear from all storage locations
    sessionStorage.removeItem(getKey('token'));
    sessionStorage.removeItem(getKey('user'));
    localStorage.removeItem(getKey('token'));
    localStorage.removeItem(getKey('user'));
    localStorage.removeItem('authToken');
    
    setToken(null);
    setUser(null);
    setEncryptionStatus(null);
  };

  const login = async (username, password) => {
    try {
      console.log('Attempting login...');
      const response = await authAPI.login(username, password);
      
      if (!response.token || !response.user) {
        throw new Error('Invalid response from server');
      }

      console.log('Login successful, storing tokens...');
        
        sessionStorage.setItem(getKey('token'), response.token);
        sessionStorage.setItem(getKey('user'), JSON.stringify(response.user));
        localStorage.setItem(getKey('token'), response.token);
        localStorage.setItem(getKey('user'), JSON.stringify(response.user));

      // Update state immediately
      setToken(response.token);
      setUser(response.user);
      
      // Initialize encryption in background
      setTimeout(() => {
        initializeUserEncryption(response.user.id).catch(console.error);
      }, 100);
      
      return { success: true, user: response.user };
    } catch (error) {
      console.error('Login failed:', error);
      clearAuthData();
      return { success: false, error: error.message };
    }
  };

  const register = async (userData) => {
    try {
      console.log('Attempting registration...');
      const response = await authAPI.register(userData);
      
      if (response.token && response.user) {
        sessionStorage.setItem(getKey('token'), response.token);
        sessionStorage.setItem(getKey('user'), JSON.stringify(response.user));
        localStorage.setItem(getKey('token'), response.token);
        localStorage.setItem(getKey('user'), JSON.stringify(response.user));
        
        setToken(response.token);
        setUser(response.user);
        
        // Initialize encryption in background
        setTimeout(() => {
          initializeUserEncryption(response.user.id).catch(console.error);
        }, 100);
        
        console.log('Registration successful');
      }
      
      return { success: true, user: response.user };
    } catch (error) {
      console.error('Registration failed:', error);
      clearAuthData();
      return { success: false, error: error.message };
    }
  };

  const getEncryptionStatus = () => {
    if (!user?.id) {
      return { hasKeys: false, error: 'No user authenticated' };
    }
    return encryptionService.getEncryptionStatus(user.id);
  };

  const isE2EEReady = () => {
    return encryptionStatus?.hasKeys === true;
  };

  const getEncryptionService = () => {
    return encryptionService;
  };

  const logout = () => {
    console.log('Logging out...');
    clearAuthData();
    };
    
    useEffect(() => {
        const handleUnload = () => {
        localStorage.removeItem(getKey('token'));
        localStorage.removeItem(getKey('user'));
        };
        window.addEventListener('beforeunload', handleUnload);
        return () => window.removeEventListener('beforeunload', handleUnload);
    }, []);

  const value = {
    user,
    token,
    isAuthenticated,
    encryptionStatus,
    isE2EEReady,     
    getEncryptionStatus, 
    getEncryptionService,
    login,
    register,
    logout,
    loading,
    tabId: TAB_ID,
    getStorageKey: getKey
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;