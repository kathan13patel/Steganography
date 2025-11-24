import { useEffect, useRef, useCallback } from 'react';

class WebSocketService {
  constructor() {
    this.socket = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectInterval = 3000;
    this.messageHandlers = new Set();
    this.connectionHandlers = new Set();
    this.currentToken = null;
    this.currentUserId = null; // Store the current user ID
  }

  connect = (token, userId) => { // Add userId parameter
    // Validate token and userId before attempting connection
    if (!token || token === 'undefined' || token === 'null') {
      console.error('Invalid token provided for WebSocket connection');
      this.connectionHandlers.forEach(handler => handler(false, 'invalid_token'));
      return;
    }

    if (!userId) {
      console.error('No user ID provided for WebSocket connection');
      this.connectionHandlers.forEach(handler => handler(false, 'no_user_id'));
      return;
    }

    // Store token and user ID for reconnection attempts
    this.currentToken = token;
    this.currentUserId = userId;

    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      return;
    }

    try {
      // Use wss:// for production, ws:// for development
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      // CORRECT: Include user ID in the path
      const wsUrl = `${protocol}//${window.location.hostname}:8001/ws/chat/${userId}?token=${encodeURIComponent(token)}`;
      console.log('Connecting to WebSocket:', wsUrl);
      this.socket = new WebSocket(wsUrl);

      this.socket.onopen = () => {
        console.log('WebSocket connected successfully');
        this.reconnectAttempts = 0;
        this.connectionHandlers.forEach(handler => handler(true, 'connected'));
      };

      this.socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          console.log('WebSocket message received:', message);
          this.messageHandlers.forEach(handler => handler(message));
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      this.socket.onclose = (event) => {
        console.log('WebSocket connection closed:', event.code, event.reason);
        this.connectionHandlers.forEach(handler => handler(false, 'disconnected'));
        this.attemptReconnect();
      };

      this.socket.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.connectionHandlers.forEach(handler => handler(false, 'error'));
      };

    } catch (error) {
      console.error('WebSocket connection failed:', error);
      this.attemptReconnect();
    }
  };

  attemptReconnect = () => {
    if (this.reconnectAttempts < this.maxReconnectAttempts && this.currentToken && this.currentUserId) {
      this.reconnectAttempts++;
      console.log(`Attempting to reconnect... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      
      setTimeout(() => {
        this.connect(this.currentToken, this.currentUserId); // Use stored token and user ID
      }, this.reconnectInterval * this.reconnectAttempts);
    } else {
      console.error('Max reconnection attempts reached or no token/user ID available');
      this.connectionHandlers.forEach(handler => handler(false, 'max_attempts_reached'));
    }
  };

  disconnect = () => {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.currentToken = null;
    this.currentUserId = null;
    this.reconnectAttempts = 0;
    this.messageHandlers.clear();
    this.connectionHandlers.clear();
  };

  updateToken = (newToken, newUserId = null) => {
    if (newToken && newToken !== this.currentToken) {
      this.currentToken = newToken;
      if (newUserId) {
        this.currentUserId = newUserId;
      }
      // If we're connected with old credentials, reconnect
      if (this.socket && this.socket.readyState === WebSocket.OPEN) {
        console.log('Credentials updated, reconnecting WebSocket...');
        this.disconnect();
        this.connect(newToken, newUserId || this.currentUserId);
      }
    }
  };

  updateToken = (newToken) => {
    if (newToken && newToken !== this.currentToken) {
      this.currentToken = newToken;
      // If we're connected with an old token, reconnect with new token
      if (this.socket && this.socket.readyState === WebSocket.OPEN) {
        console.log('Token updated, reconnecting WebSocket...');
        this.disconnect();
        this.connect(newToken);
      }
    }
  };

  sendMessage = (message) => {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      try {
        this.socket.send(JSON.stringify(message));
        return true;
      } catch (error) {
        console.error('Error sending message:', error);
        return false;
      }
    } else {
      console.warn('WebSocket is not connected');
      return false;
    }
  };

  addMessageHandler = (handler) => {
    this.messageHandlers.add(handler);
    return () => this.messageHandlers.delete(handler);
  };

  addConnectionHandler = (handler) => {
    this.connectionHandlers.add(handler);
    return () => this.connectionHandlers.delete(handler);
  };

  getConnectionStatus = () => {
    if (!this.socket) return 'disconnected';
    switch (this.socket.readyState) {
      case WebSocket.CONNECTING:
        return 'connecting';
      case WebSocket.OPEN:
        return 'connected';
      case WebSocket.CLOSING:
        return 'closing';
      case WebSocket.CLOSED:
        return 'disconnected';
      default:
        return 'unknown';
    }
  };
}

// Create a singleton instance
export const webSocketService = new WebSocketService();

// React hook for using WebSocket
export const useWebSocket = (onMessage, onConnectionChange, initialToken = null, initialUserId = null) => {
  const messageHandlerRef = useRef();
  const connectionHandlerRef = useRef();
  const tokenRef = useRef(initialToken);
  const userIdRef = useRef(initialUserId);

  useEffect(() => {
    messageHandlerRef.current = onMessage;
    connectionHandlerRef.current = onConnectionChange;
  }, [onMessage, onConnectionChange]);

  useEffect(() => {
    if (initialToken) {
      tokenRef.current = initialToken;
    }
    if (initialUserId) {
      userIdRef.current = initialUserId;
    }
  }, [initialToken, initialUserId]);

  const connect = useCallback((token = null, userId = null) => {
    const effectiveToken = token || tokenRef.current;
    const effectiveUserId = userId || userIdRef.current;
    
    if (effectiveToken && effectiveUserId) {
      webSocketService.connect(effectiveToken, effectiveUserId);
    } else {
      console.error('No token or user ID provided for WebSocket connection');
      if (connectionHandlerRef.current) {
        connectionHandlerRef.current(false, 'missing_credentials');
      }
    }
  }, []);

  const disconnect = useCallback(() => {
    webSocketService.disconnect();
  }, []);

  const send = useCallback((message) => {
    return webSocketService.sendMessage(message);
  }, []);

  const updateCredentials = useCallback((newToken, newUserId) => {
    tokenRef.current = newToken;
    if (newUserId) {
      userIdRef.current = newUserId;
    }
    webSocketService.updateToken(newToken, newUserId);
  }, []);

  useEffect(() => {
    const cleanupMessageHandler = webSocketService.addMessageHandler(
      (message) => messageHandlerRef.current?.(message)
    );

    const cleanupConnectionHandler = webSocketService.addConnectionHandler(
      (connected, reason) => connectionHandlerRef.current?.(connected, reason)
    );

    return () => {
      cleanupMessageHandler();
      cleanupConnectionHandler();
    };
  }, []);

  return {
    connect,
    disconnect,
    send,
    updateCredentials,
    getStatus: webSocketService.getConnectionStatus,
    isConnected: webSocketService.getConnectionStatus() === 'connected'
  };
};;

// Message types (unchanged)
export const MESSAGE_TYPES = {
  TEXT: 'text',
  FILE: 'file',
  IMAGE: 'image',
  AUDIO: 'audio',
  VIDEO: 'video',
  STATUS: 'status',
  TYPING: 'typing',
  READ_RECEIPT: 'read_receipt'
};

// Message status (unchanged)
export const MESSAGE_STATUS = {
  SENDING: 'sending',
  SENT: 'sent',
  DELIVERED: 'delivered',
  READ: 'read',
  FAILED: 'failed'
};

// Utility functions (unchanged)
export const createMessage = (type, data) => ({
  id: Date.now() + Math.random().toString(36).substr(2, 9),
  type,
  timestamp: new Date().toISOString(),
  ...data
});

export const isMessageType = (message, type) => message.type === type;