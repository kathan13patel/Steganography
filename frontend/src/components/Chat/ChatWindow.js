import React, { useState, useRef, useEffect, useCallback  } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../services/auth';
import useDynamicCharCapacity from './useDynamicCharCapacity';
import MediaPreviewModal from './MediaPreviewModal';
import { API_CONFIG, WS_ENDPOINTS } from '../../config';
import { chatAPI, e2eeAPI } from '../../services/api';
import encryptionService from '../../services/encryptionService';
import '@fortawesome/fontawesome-free/css/all.min.css';
import './css/Chat.css';

const ChatWindow = () => {
    const { userId } = useParams();
    const navigate = useNavigate();
    const location = useLocation();
    const { user: currentUser, token, logout, isE2EEReady, getEncryptionService } = useAuth(); 
    const [isE2EEEnabled, setIsE2EEEnabled] = useState(false);
    const [encryptionStatus, setEncryptionStatus] = useState('checking');
    const [showEncryptionInfo, setShowEncryptionInfo] = useState(false);
    const [targetUser, setTargetUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [showLoginPrompt, setShowLoginPrompt] = useState(false);
    const [message, setMessage] = useState('');
    const [selectedFile, setSelectedFile] = useState(null);
    const [fileType, setFileType] = useState('image');
    const [operationMode, setOperationMode] = useState('encode');
    const [isProcessing, setIsProcessing] = useState(false);
    const [messages, setMessages] = useState([]);
    const [onlineStatus, setOnlineStatus] = useState(false);
    const [isTyping, setIsTyping] = useState(false);
    const [connectionStatus, setConnectionStatus] = useState('disconnected');
    const [isPolling, setIsPolling] = useState(false);
    const [selectedChatPartner, setSelectedChatPartner] = useState(null);
    const [messageType, setMessageType] = useState('text');
    const messagesEndRef = useRef(null);
    const prevMessages = useRef([]);
    const scrollTimeoutRef = useRef(null);
    const ws = useRef(null);
    const reconnectTimeout = useRef(null);
    const reconnectAttempts = useRef(0);
    const pollingInterval = useRef(null);
    const isConnecting = useRef(false);
    const [selectedMedia, setSelectedMedia] = useState(null);
    const [isMediaModalOpen, setIsMediaModalOpen] = useState(false);
    const maxReconnectAttempts = 5;
    const [maxCharLimit, setMaxCharLimit] = useState(0);
    const [charLimitInfo, setCharLimitInfo] = useState('');
    const [showScrollToBottom, setShowScrollToBottom] = useState(false);
    const [isNearBottom, setIsNearBottom] = useState(true);
    const calculateMaxCharCapacity = useDynamicCharCapacity();
    const [deleteModalOpen, setDeleteModalOpen] = useState(false);
    const [messageToDelete, setMessageToDelete] = useState(null);
    const [isDeleting, setIsDeleting] = useState(false);
    const [isUserInteracting, setIsUserInteracting] = useState(false);
    const [lastPollTime, setLastPollTime] = useState(0);    
    const isUserScrolling = useRef(false);
    const [activeMenu, setActiveMenu] = useState(null);
    const menuRef = useRef(null);
    const userScrolledUp = useRef(false);
    const isCurrentUserLastSender = useRef(false);
    const messagesContainerRef = useRef(null);
    const userManuallyScrolled = useRef(false);

    useEffect(() => {
        const initializeE2EESystem = async () => {
            try {
                console.log(' Initializing E2EE system...');
                setEncryptionStatus('initializing');
                
                const success = await e2eeAPI.initialize();
                if (success) {
                    console.log('E2EE system initialized');
                    setEncryptionStatus('ready');
                    setIsE2EEEnabled(true);
                } else {
                    console.warn('E2EE initialization failed');
                    setEncryptionStatus('failed');
                    setIsE2EEEnabled(false);
                }
            } catch (error) {
                console.error('E2EE initialization error:', error);
                setEncryptionStatus('error');
                setIsE2EEEnabled(false);
            }
        };

        initializeE2EESystem();
    }, []);

    useEffect(() => {
        const initializeSecureConversation = async () => {
            if (!targetUser?.id || !currentUser?.id || !e2eeAPI.isReady()) {
                return;
            }

            try {
                console.log(' Initializing secure conversation with:', targetUser.id);
                setEncryptionStatus('establishing');
                
                await e2eeAPI.initializeConversation(targetUser.id, token);
                
                console.log('Secure conversation established');
                setEncryptionStatus('active');
                setIsE2EEEnabled(true);
                
            } catch (error) {
                console.error('Secure conversation failed:', error);
                setEncryptionStatus('failed');
                setIsE2EEEnabled(false);
            }
        };

        if (targetUser?.id && e2eeAPI.isReady()) {
            initializeSecureConversation();
        }
    }, [targetUser?.id, currentUser?.id, token]);

    const handleMediaClick = (media) => {
        setSelectedMedia(media);
        setIsMediaModalOpen(true);
    };

    const checkIsNearBottom = useCallback(() => {
        const container = messagesContainerRef.current;
        if (!container) return true;
        const { scrollTop, scrollHeight, clientHeight } = container;
        const distanceFromBottom = scrollHeight - scrollTop - clientHeight;
        return distanceFromBottom <= 100;
    }, []);

    // Handle scroll
    const handleScroll = useCallback(() => {
        const nearBottom = checkIsNearBottom();
        setIsNearBottom(nearBottom);
        setShowScrollToBottom(!nearBottom);
        
        // If user scrolls away from bottom, mark as manual scroll
        if (!nearBottom) {
            userManuallyScrolled.current = true;
        }
    }, [checkIsNearBottom]);

    // Scroll to bottom
    const scrollToBottom = useCallback(() => {
        const container = messagesContainerRef.current;
        if (container) {
            container.scrollTo({
                top: container.scrollHeight,
                behavior: "smooth",
            });
            setIsNearBottom(true);
            setShowScrollToBottom(false);
            userManuallyScrolled.current = false; // Reset since we're going to bottom
        }
    }, []);

    // SIMPLE PERMANENT SOLUTION
    useEffect(() => {
        const container = messagesContainerRef.current;
        if (!container || messages.length === 0) return;

        const lastMessage = messages[messages.length - 1];
        const isCurrentUserSender = lastMessage && 
            normalizeUserId(lastMessage.sender_id) === normalizeUserId(currentUser?.id);
        
        // ONLY auto-scroll if:
        // 1. Current user sent a message, OR
        // 2. User hasn't manually scrolled up
        if (!userManuallyScrolled.current || (isCurrentUserSender && isNearBottom)) {
            requestAnimationFrame(() => {
                scrollToBottom();
            });
        }
        // If user manually scrolled up and it's not their message, DO NOT auto-scroll

        prevMessages.current = messages;
    }, [messages, scrollToBottom, currentUser, isNearBottom]);

    useEffect(() => {
        const container = messagesContainerRef.current;
        if (container) {
            container.addEventListener('scroll', handleScroll);
            return () => container.removeEventListener('scroll', handleScroll);
        }
    }, [handleScroll]);

    // Manual scroll to bottom button
    const handleScrollToBottomClick = () => {
        scrollToBottom();
    };
    
    // Add this helper function at the top of your component
    const normalizeUserId = (userId) => {
        if (!userId) return null;

        // Handle string IDs
        if (typeof userId === 'string') {
            // Remove ObjectId wrapper if present
            return userId.replace(/^ObjectId\("|"\)$/g, '');
        }

        // Handle MongoDB ObjectId objects
        if (userId && typeof userId === 'object' && userId.toString) {
            return userId.toString();
        }

        // Handle numbers
        if (typeof userId === 'number') {
            return userId.toString();
        }

        return null;
    };

    useEffect(() => {
        return () => {
            console.log('Cleaning up WebSocket connection');
            if (ws.current) {
                ws.current.close();
                ws.current = null;
            }
            if (reconnectTimeout.current) {
                clearTimeout(reconnectTimeout.current);
            }
        };
    }, []);

    useEffect(() => {
        console.log('Current token:', token);
        console.log('Token type:', typeof token);
        console.log('Token valid:', token && token !== 'undefined' && token !== 'null');
        console.log('Token Debug:', {
            tokenFromAuth: token,
            localStorageToken: localStorage.getItem('authToken'),
            sessionStorageToken: sessionStorage.getItem('authToken'),
            allLocalStorage: Object.keys(localStorage),
            hasAuthToken: !!localStorage.getItem('authToken')
        });
    }, [token]);

    const getAuthToken = () => {
        // First try the auth context token
        if (token && typeof token === 'string' && token.length > 10) {
            return token;
        }

        // Then try localStorage
        const localToken = localStorage.getItem('authToken') || localStorage.getItem('token');
        if (localToken && typeof localToken === 'string' && localToken.length > 10) {
            return localToken;
        }

        // Then try sessionStorage
        const sessionToken = sessionStorage.getItem('authToken') || sessionStorage.getItem('token');
        if (sessionToken && typeof sessionToken === 'string' && sessionToken.length > 10) {
            return sessionToken;
        }

        console.error('No valid authentication token found');
        return null;
    };

    useEffect(() => {
        const initializeChat = async () => {
            try {
                const authToken = getAuthToken();

                if (!authToken) {
                    console.error('No authentication token found');
                    setConnectionStatus('error');
                    return;
                }

                let userData = location.state?.user;
                if (!userData && userId) {
                    userData = await fetchUserData(userId);
                }

                if (userData) {
                    setTargetUser(userData);
                    setError('');

                    // Try WebSocket first
                    connectWebSocket();

                    // Fall back to HTTP polling after 3 seconds if WebSocket fails
                    const fallbackTimer = setTimeout(() => {
                        if (connectionStatus !== 'connected') {
                            startHttpPolling(userData.id);
                        }
                    }, 3000);

                    return () => clearTimeout(fallbackTimer);
                }
            } catch (err) {
                console.error('Error initializing chat:', err);
                setError('Failed to load chat');
            } finally {
                setLoading(false);
            }
        };

        initializeChat();

        return () => {
            // Cleanup
            if (ws.current) {
                ws.current.close(1000, 'Component unmounting');
            }
            if (reconnectTimeout.current) {
                clearTimeout(reconnectTimeout.current);
            }
            stopHttpPolling(); // This will clear the interval
        };
    }, [userId, location.state]);

    // Add this useEffect to automatically refresh messages
    useEffect(() => {
        if (targetUser?.id) {
            // Initial fetch
            fetchMessages(targetUser.id);

            // Set up polling interval for real-time updates
            const interval = setInterval(() => {
                fetchMessages(targetUser.id);
            }, 3000); // Poll every 3 seconds

            return () => clearInterval(interval);
        }
    }, [targetUser?.id]);

    // Handle message change with character limit
    const handleMessageChange = (event) => {
        const newMessage = event.target.value;
        if (operationMode !== 'decode') {
            if (newMessage.length <= maxCharLimit) {
                setMessage(newMessage);
            } else {
                // Truncate to max limit if pasted content exceeds limit
                setMessage(newMessage.substring(0, maxCharLimit));
            }
        }
    };

    const fetchUserData = async (userId) => {
        const authToken = getAuthToken();

        if (!authToken) {
            console.error('Invalid token when fetching user data');
            setError('Authentication token is invalid. Please log in again.');
            return null;
        }

        try {
            const response = await fetch(`${API_CONFIG.BASE_URL}/api/users/${userId}`, {
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });

            if (response.ok) {
                return await response.json();
            } else if (response.status === 401) {
                // Token is invalid/expired
                console.error('Token expired or invalid');
                setError('Your session has expired. Please log in again.');
                return null;
            } else {
                throw new Error('Failed to fetch user data');
            }
        } catch (error) {
            console.error('Error fetching user:', error);
            throw error;
        }
    };

    console.log('=== WEB SOCKET URL DEBUG ===');
    // Call the function to get the actual token value
    const authTokenValue = getAuthToken();
    console.log('Current user ID:', currentUser);
    console.log('Token from context:', token);
    console.log('Token from getAuthToken():', authTokenValue);
    console.log('Token exists:', !!authTokenValue);
    console.log('Token type:', typeof authTokenValue);
    console.log('Token length:', authTokenValue ? authTokenValue.length : 0);
    console.log('Token preview:', authTokenValue ? authTokenValue.substring(0, 50) + '...' : 'null');
    console.log('Encoded token:', authTokenValue ? encodeURIComponent(authTokenValue).substring(0, 50) + '...' : 'null');
    console.log('Full URL:', `ws://localhost:8001/ws/chat/${currentUser?.id}?token=${authTokenValue ? encodeURIComponent(authTokenValue) : 'null'}`);
    console.log('============================');

    // In your ChatWindow.js, modify the WebSocket connection logic:
    const connectWebSocket = () => {
        if (ws.current || !targetUser || isConnecting.current) return;

        const authToken = getAuthToken();
        const currentUserId = currentUser?.id || currentUser?._id;

        if (!authToken || !currentUserId) {
            setConnectionStatus('polling');
            startHttpPolling(targetUser.id);
            return;
        }

        isConnecting.current = true;
        setConnectionStatus('connecting');

        const connectionTimeout = setTimeout(() => {
            if (ws.current && ws.current.readyState === WebSocket.CONNECTING) {
                console.log('⏰ WebSocket connection timeout');
                ws.current.close();
                setConnectionStatus('timeout');
                isConnecting.current = false;
                startHttpPolling(targetUser.id);
            }
        }, 5000);

        try {
            // Use the correct WebSocket URL format
            const wsUrl = `ws://localhost:8001/ws/chat/${currentUserId}/${targetUser.id}?token=${encodeURIComponent(authToken)}`;
            console.log('Attempting WebSocket connection to:', wsUrl);

            ws.current = new WebSocket(wsUrl);

            ws.current.onopen = () => {
                clearTimeout(connectionTimeout);
                console.log('WebSocket connected successfully');
                isConnecting.current = false;
                setConnectionStatus('connected');
                setOnlineStatus(true);
            };

            ws.current.onerror = (error) => {
                clearTimeout(connectionTimeout);
                console.error('WebSocket connection error:', error);
                setConnectionStatus('error');
                isConnecting.current = false;
                startHttpPolling(targetUser.id);
            };

            ws.current.onclose = (event) => {
                clearTimeout(connectionTimeout);
                console.log('WebSocket closed:', event.code, event.reason);
                setConnectionStatus('disconnected');
                setOnlineStatus(false);
                isConnecting.current = false;

                if (event.code !== 1000) {
                    setTimeout(() => {
                        if (!ws.current) {
                            console.log('Attempting to reconnect WebSocket...');
                            connectWebSocket();
                        }
                    }, 2000);
                }
            };

            ws.current.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    console.log('WebSocket message received:', message);
                    handleWebSocketMessage(message);
                } catch (error) {
                    console.error('Error parsing message:', error);
                }
            };

        } catch (error) {
            clearTimeout(connectionTimeout);
            console.error('WebSocket connection failed:', error);
            setConnectionStatus('error');
            isConnecting.current = false;
            startHttpPolling(targetUser.id);
        }
    };

    // Modify your useEffect to handle WebSocket failures gracefully
    useEffect(() => {
        if (targetUser && getAuthToken()) { // Call the function to check if token exists
            connectWebSocket();

            // Set up HTTP polling as fallback
            const pollInterval = setInterval(() => {
                if (targetUser && targetUser.id) {
                    fetchMessages(targetUser.id);
                }
            }, 5000);

            return () => {
                clearInterval(pollInterval);
                if (ws.current) {
                    ws.current.close();
                    ws.current = null;
                }
            };
        }
    }, [targetUser, token]); // Use token instead of getAuthToken function

    const checkWebSocketServer = async () => {
        try {
            // Simple HTTP request to check if server is reachable
            const response = await fetch('http://localhost:8001/', {
                method: 'GET',
                mode: 'no-cors', // This will work for WebSocket server check
            });
            return true;
        } catch (error) {
            console.log('WebSocket server check failed:', error);
            return false;
        }
    };

    const sendWebSocketMessage = (data) => {
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
            try {
                ws.current.send(JSON.stringify(data));
                console.log('WebSocket message sent:', data);
                return true;
            } catch (error) {
                console.error('Error sending WebSocket message:', error);
                return false;
            }
        } else {
            console.warn('WebSocket is not open. Current state:',
                ws.current ?
                    ws.current.readyState === WebSocket.CONNECTING ? 'CONNECTING' :
                        ws.current.readyState === WebSocket.CLOSING ? 'CLOSING' :
                            ws.current.readyState === WebSocket.CLOSED ? 'CLOSED' : 'UNKNOWN'
                    : 'no connection'
            );
            return false;
        }
    };

    const handleWebSocketDisconnection = (targetUserId) => {
        // Attempt to reconnect with exponential backoff
        if (reconnectAttempts.current < maxReconnectAttempts) {
            reconnectAttempts.current += 1;
            const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);

            console.log(`Attempting to reconnect in ${delay}ms (attempt ${reconnectAttempts.current}/${maxReconnectAttempts})`);

            reconnectTimeout.current = setTimeout(() => {
                connectWebSocket(targetUserId);
            }, delay);
        } else {
            // Max reconnection attempts reached, fall back to HTTP polling
            console.log('Max reconnection attempts reached. Falling back to HTTP polling');
            startHttpPolling(targetUserId);
        }
    };

    const startHttpPolling = (targetUserId) => {
        console.log('Starting HTTP polling for user:', targetUserId);
        setConnectionStatus('polling');
        setIsPolling(true);

        fetchMessages(targetUserId);

        const pollInterval = 2000; // 2 seconds instead of 5
        const interval = setInterval(() => {
            const now = Date.now();
            const timeSinceLastPoll = now - lastPollTime;
            
            // Skip polling if:
            // - Modal is open
            // - User is interacting
            // - Too soon since last poll
            // - Processing something
            if (deleteModalOpen || isDeleting || isProcessing || isUserInteracting || timeSinceLastPoll < 2000) {
                console.log('⏸️ Skipping poll - conditions not met');
                return;
            }
            
            console.log('Polling for new messages...');
            fetchMessages(targetUserId);
            setLastPollTime(now);
        }, pollInterval);


        pollingInterval.current = interval;
    };

    const stopHttpPolling = () => {
        if (pollingInterval.current) {
            clearInterval(pollingInterval.current);
            pollingInterval.current = null;
        }
        setIsPolling(false);
    };

    const fetchMessages = async (targetUserId) => {
        try {
            console.log(' Fetching messages between:', currentUser?.id, 'and', targetUserId);

            const authToken = getAuthToken();
            if (!authToken) {
                console.error('No auth token available for fetching messages');
                return;
            }

            // CORRECTED: Fetch messages between current user AND target user
            const response = await fetch(
                `${API_CONFIG.BASE_URL}/api/messages/${targetUserId}`, // Fixed endpoint
                {
                    headers: {
                        'Authorization': `Bearer ${authToken}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const responseData = await response.json();
            console.log('Conversation messages:', responseData);

            // Process messages
            if (responseData.success && Array.isArray(responseData.messages)) {
                const processedMessages = responseData.messages.map(msg => ({
                    id: msg._id || msg.id,
                    sender_id: msg.sender_id,
                    receiver_id: msg.receiver_id,
                    content: msg.content,
                    timestamp: msg.timestamp || msg.createdAt,
                    file: msg.file,
                    sender_name: normalizeUserId(msg.sender_id) === normalizeUserId(currentUser?.id)
                        ? 'You'
                        : (targetUser?.username || 'Unknown')
                }));

                setMessages(processedMessages);
            }
        } catch (err) {
            console.error('Error fetching messages:', err);
            setError('Failed to load messages. Please try again.');
        }
    };

    const handleWebSocketMessage = (data) => {
        console.log('Incoming WebSocket message:', data);
        console.log('Current user ID:', currentUser?.id);
        console.log('Target user ID:', targetUser?.id);

        switch (data.type) {
            case 'connection_established':
                console.log('WebSocket connection confirmed by server');
                setConnectionStatus('connected');

                // Request messages for the target user
                if (ws.current && ws.current.readyState === WebSocket.OPEN) {
                    console.log('Requesting messages for conversation between:');
                    console.log('   - Current user:', currentUser.id);
                    console.log('   - Target user:', targetUser.id);

                    ws.current.send(JSON.stringify({
                        type: 'get_messages',
                        target_user_id: targetUser.id,
                        current_user_id: currentUser.id  // Add current user ID for clarity
                    }));
                }
                break;

            case 'message':
                console.log('New message received:', data.message);
                console.log('Message sender:', data.message.sender_id);
                console.log('Message receiver:', data.message.receiver_id);

                // Check if this message belongs to the current conversation
                const normalizedSender = normalizeUserId(data.message.sender_id);
                const normalizedReceiver = normalizeUserId(data.message.receiver_id);
                const normalizedCurrent = normalizeUserId(currentUser?.id);
                const normalizedTarget = normalizeUserId(targetUser?.id);

                const isRelevantMessage =
                    (normalizedSender === normalizedCurrent && normalizedReceiver === normalizedTarget) ||
                    (normalizedSender === normalizedTarget && normalizedReceiver === normalizedCurrent);

                console.log('Is relevant to current conversation:', isRelevantMessage);

                if (!isRelevantMessage) {
                    console.log('Ignoring message not relevant to current conversation');
                    return; // Don't process irrelevant messages
                }

                setMessages(prevMessages => {
                    // Check if message already exists to avoid duplicates
                    const messageExists = prevMessages.some(msg =>
                        (msg.id && data.message.id && msg.id === data.message.id) ||
                        (msg._id && data.message._id && msg._id === data.message._id) ||
                        (msg.timestamp === data.message.timestamp && msg.sender_id === data.message.sender_id)
                    );

                    if (!messageExists) {
                        console.log('Adding new message to state');
                        // Ensure the message has all required properties
                        const newMessage = {
                            ...data.message,
                            id: data.message.id || data.message._id || `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                            timestamp: data.message.timestamp || new Date().toISOString()
                        };
                        return [...prevMessages, newMessage];
                    }
                    console.log('Message already exists, skipping');
                    return prevMessages;
                });
                break;

            case 'messages':
                // Handle bulk messages response
                console.log('Received messages batch:', data.messages);

                // Filter to only show messages relevant to this conversation
                const relevantMessages = (data.messages || []).filter(msg => {
                    const normalizedSender = normalizeUserId(msg.sender_id);
                    const normalizedReceiver = normalizeUserId(msg.receiver_id);
                    const normalizedCurrent = normalizeUserId(currentUser?.id);
                    const normalizedTarget = normalizeUserId(targetUser?.id);

                    return (
                        (normalizedSender === normalizedCurrent && normalizedReceiver === normalizedTarget) ||
                        (normalizedSender === normalizedTarget && normalizedReceiver === normalizedCurrent)
                    );
                });

                console.log('Relevant messages:', relevantMessages);

                if (relevantMessages.length > 0) {
                    // Ensure all messages have proper IDs
                    const processedMessages = relevantMessages.map(msg => ({
                        ...msg,
                        id: msg.id || msg._id || `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
                    }));
                    setMessages(processedMessages);
                } else if (data.data && Array.isArray(data.data)) {
                    // Handle alternative response format
                    const relevantData = data.data.filter(msg => {
                        const normalizedSender = normalizeUserId(msg.sender_id);
                        const normalizedReceiver = normalizeUserId(msg.receiver_id);
                        const normalizedCurrent = normalizeUserId(currentUser?.id);
                        const normalizedTarget = normalizeUserId(targetUser?.id);

                        return (
                            (normalizedSender === normalizedCurrent && normalizedReceiver === normalizedTarget) ||
                            (normalizedSender === normalizedTarget && normalizedReceiver === normalizedCurrent)
                        );
                    });

                    const processedMessages = relevantData.map(msg => ({
                        ...msg,
                        id: msg.id || msg._id || `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
                    }));
                    setMessages(processedMessages);
                }
                break;

            case 'ping':
                // Respond to ping
                if (ws.current && ws.current.readyState === WebSocket.OPEN) {
                    ws.current.send(JSON.stringify({
                        type: 'pong',
                        timestamp: new Date().toISOString()
                    }));
                }
                break;

            default:
                console.log('Unknown message type:', data.type);
        }
    };

    const handleSend = async () => {
        const authToken = getAuthToken();
        
        // Call debug function first
        debugE2EEStatus();

        if (operationMode === 'encode' && !selectedFile) {
            alert('Please select a file to encode');
            return;
        }

        if (operationMode === 'text' && !message.trim()) {
            alert('Please enter a message to send');
            return;
        }

        setIsProcessing(true);

        try {
            if (operationMode === 'encode') {
                await handleEncodeMessage();
            } else if (operationMode === 'text') {
                await handleTextMessage();
            } else {
                await handleDecodeMessage();
            }
        } catch (error) {
            console.error('FINAL ERROR - handleSend failed:', error);
            
            if (operationMode === 'decode') {
                await sendDecodeErrorMessage();
            }
            
            alert(`Error: ${error.message}`);
        } finally {
            setIsProcessing(false);
        }
    };

    // Helper function for encode mode
    const handleEncodeMessage = async () => {
        console.log('Starting encode message process...');
        
        const formData = new FormData();
        formData.append('file', selectedFile);
        
        // E2EE Encryption for file message
        let messageToEncode = message;
        let fileEncryptionInfo = { enabled: false };

        if (isE2EEEnabled && e2eeAPI.isReady()) {
            try {
                console.log('Encrypting message for file steganography...');
                const keyManager = await e2eeAPI.getKeyManager();
                const encryptedContent = await keyManager.encryptMessage(message, targetUser.id);
                messageToEncode = JSON.stringify(encryptedContent);
                fileEncryptionInfo = {
                    enabled: true,
                    algorithm: encryptedContent.algo
                };
                console.log('Message encrypted for file steganography');
            } catch (encryptError) {
                console.warn('File encryption failed, using plaintext:', encryptError);
                fileEncryptionInfo = { enabled: false, error: encryptError.message };
            }
        }
        
        formData.append('message', messageToEncode);
        formData.append('sender_id', currentUser.id);
        formData.append('receiver_id', targetUser.id);
        formData.append('file_type', fileType);

        console.log('Sending encode request...');
        const response = await fetch(`${API_CONFIG.BASE_URL}/api/encode`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${getAuthToken()}`
            },
            body: formData,
        });

        console.log('Encode response status:', response.status);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Encode failed:', response.status, errorText);
            throw new Error(`Failed to encode message: ${response.status}`);
        }

        const result = await response.json();
        console.log('Encode success:', result);

        // Check if we have the required URL for the encoded file
        if (!result.stego_url && !result.file_url) {
            console.error('No file URL returned from encode API');
            throw new Error('Encoding failed: No file URL returned');
        }

        // Create message data with the encoded file
        const messageData = {
            sender_id: currentUser.id,
            receiver_id: targetUser.id,
            content: message, // The original message
            encrypted_content: {}, // Empty for file messages
            file: {
                name: selectedFile.name,
                type: fileType,
                url: result.stego_url || result.file_url,
                original_url: result.original_url || result.file_url,
                is_encrypted: fileEncryptionInfo.enabled,
                // Add file size and other metadata for better display
                size: selectedFile.size,
                stego_success: true
            },
            timestamp: new Date().toISOString(),
            encryption: fileEncryptionInfo,
            message_type: 'file' // Important: Mark this as a file message
        };

        console.log('Sending encoded file message to server...', messageData);
        
        // Send the message via HTTP
        const httpResult = await sendHttpMessage(messageData);
        
        if (httpResult.success) {
            console.log('Encoded message sent successfully via HTTP');
            
            // Create the message for immediate display with proper structure
            const newMessage = {
                id: httpResult.result?.message_id || `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                sender_id: currentUser.id,
                receiver_id: targetUser.id,
                content: message, // Keep the original message content
                file: {
                    name: selectedFile.name,
                    type: fileType,
                    url: result.stego_url || result.file_url,
                    original_url: result.original_url || result.file_url,
                    is_encrypted: fileEncryptionInfo.enabled,
                    size: selectedFile.size
                },
                timestamp: new Date().toISOString(),
                encryption: fileEncryptionInfo,
                message_type: 'file',
                sender_name: 'You',
                status: 'sent'
            };

            console.log('Adding encoded message to local state:', newMessage);
            
            // Add to local state for immediate display
            setMessages(prev => [...prev, newMessage]);
            
            // Clear input
            setMessage('');
            setSelectedFile(null);
            
            // Force refresh messages to ensure sync with server
            setTimeout(() => {
                console.log('Refreshing messages from server...');
                fetchMessages(targetUser.id);
            }, 500);
            
        } else {
            console.error('Failed to send encoded message:', httpResult.error);
            throw new Error(`Failed to save message: ${httpResult.error}`);
        }
    };
    
    const handleTextMessage = async () => {
        console.log('Starting text message send process');
        
        let messageToSend = message;
        let encryptedContent = {};
        let encryptionInfo = { enabled: false };

        console.log(' E2EE STATUS CHECK:', {
            isE2EEEnabled: isE2EEEnabled,
            encryptionStatus: encryptionStatus
        });

        // Apply E2EE for text messages when properly enabled
        if (isE2EEEnabled && encryptionStatus === 'active' && e2eeAPI.isReady()) {
            try {
                console.log('Encrypting text message...');
                const keyManager = await e2eeAPI.getKeyManager();
                const encryptedData = await keyManager.encryptMessage(message, targetUser.id);
                
                // For text messages: store encrypted data in encrypted_content
                encryptedContent = encryptedData;
                encryptionInfo = {
                    enabled: true,
                    algorithm: encryptedData.algo,
                    type: 'text'
                };
                
                console.log('Text message encrypted successfully');
            } catch (encryptError) {
                console.warn('Text encryption failed, using plaintext:', encryptError);
                encryptionInfo = { 
                    enabled: false, 
                    error: encryptError.message,
                    type: 'text'
                };
            }
        } else {
            console.log('ℹ️ E2EE not active, sending plain text');
            encryptionInfo = { 
                enabled: false, 
                reason: 'E2EE not available',
                type: 'text'
            };
        }

        // Prepare message data
        const messageData = {
            sender_id: currentUser.id,
            receiver_id: targetUser.id,
            content: messageToSend, // Always keep original content
            encrypted_content: encryptionInfo.enabled ? encryptedContent : {},
            timestamp: new Date().toISOString(),
            encryption: encryptionInfo,
            message_type: 'text' // Explicitly mark as text message
        };

        console.log('Final message data for server:', messageData);

        // Create local message for immediate display
        const localMessage = {
            id: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            sender_id: currentUser.id,
            receiver_id: targetUser.id,
            content: messageToSend, // Use original content for display
            encrypted_content: encryptionInfo.enabled ? encryptedContent : {},
            timestamp: new Date().toISOString(),
            encryption: encryptionInfo,
            message_type: 'text',
            sender_name: 'You',
            status: 'sending'
        };

        console.log('Local message for display:', localMessage);

        // Add to local state immediately
        setMessages(prev => [...prev, localMessage]);
        setMessage(''); // Clear input immediately

        // Send the message
        let sendSuccess = false;
        
        // Try WebSocket first
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
            console.log('Attempting WebSocket send...');
            sendSuccess = sendWebSocketMessage({
                type: 'message',
                message: messageData
            });
            
            if (sendSuccess) {
                console.log('Message sent via WebSocket');
            }
        }

        // Use HTTP as primary method
        console.log('Using HTTP send (primary method)...');
        const httpResult = await sendHttpMessage(messageData);
        
        if (httpResult.success) {
            console.log('Message sent successfully via HTTP');
            sendSuccess = true;
            
            // Update the message with real ID from server
            if (httpResult.result?.message_id) {
                setMessages(prev => prev.map(msg => 
                    msg.id === localMessage.id 
                        ? { 
                            ...msg, 
                            id: httpResult.result.message_id, 
                            status: 'sent',
                            _synced: true 
                        }
                        : msg
                ));
            } else {
                setMessages(prev => prev.map(msg => 
                    msg.id === localMessage.id 
                        ? { ...msg, status: 'sent', _synced: true }
                        : msg
                ));
            }
        } else {
            console.error('HTTP send failed:', httpResult.error);
            
            setMessages(prev => prev.map(msg => 
                msg.id === localMessage.id 
                    ? { ...msg, status: 'failed', error: httpResult.error }
                    : msg
            ));
            
            throw new Error(`Failed to send message: ${httpResult.error}`);
        }

        // Refresh messages after a delay to sync with server
        if (sendSuccess) {
            setTimeout(() => {
                console.log('Refreshing messages to sync with server...');
                fetchMessages(targetUser.id);
            }, 1500);
        }
    };

    const handleDecodeMessage = async () => {
        console.log('Starting decode process...');
        
        // Set processing state immediately
        setIsProcessing(true);
        
        try {
            const formData = new FormData();
            formData.append('file', selectedFile);

            console.log('Sending decode request...');
            const response = await fetch(`${API_CONFIG.BASE_URL}/api/decode`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${getAuthToken()}`
                },
                body: formData,
            });

            console.log('Decode response status:', response.status);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('Decode failed:', response.status, errorText);
                
                let errorMessage = 'Decoding failed: Server error';
                if (response.status === 400) {
                    errorMessage = 'Invalid file format or no hidden message found';
                } else if (response.status === 413) {
                    errorMessage = 'File too large for decoding';
                } else if (response.status === 500) {
                    errorMessage = 'Server error during decoding';
                }
                
                setMessage(errorMessage);
                return;
            }

            const result = await response.json();
            console.log('Decode API result:', result);
            
            let decodedMessage = result.decoded_message || result.message || result.data;
            
            // Check if we actually got a message
            if (!decodedMessage || decodedMessage.trim() === '') {
                setMessage('No hidden message found in this file');
                return;
            }

            // Attempt decryption if message appears to be encrypted
            if (decodedMessage && isE2EEEnabled && e2eeAPI.isReady()) {
                try {
                    // Check if it's JSON encrypted data
                    if (decodedMessage.startsWith('{') && decodedMessage.includes('iv') && decodedMessage.includes('ciphertext')) {
                        console.log('Attempting to decrypt file message...');
                        const possibleEncryptedData = JSON.parse(decodedMessage);
                        if (possibleEncryptedData.iv && possibleEncryptedData.ciphertext) {
                            const keyManager = await e2eeAPI.getKeyManager();
                            const decrypted = await keyManager.decryptMessage(possibleEncryptedData, targetUser.id);
                            decodedMessage = decrypted;
                            console.log('Successfully decrypted file message');
                        }
                    }
                } catch (e) {
                    console.log('Message is not encrypted or decryption failed, using as-is');
                }
            }
            
            // Set the final decoded message
            setMessage(decodedMessage);
            console.log('Message successfully decoded:', decodedMessage);

        } catch (error) {
            console.error('Decode process error:', error);
            setMessage('Decoding failed: ' + (error.message || 'Unknown error'));
        } finally {
            // Always clear processing state
            setIsProcessing(false);
        }
    };

    // Updated sendHttpMessage function (make sure this is included)
    const sendHttpMessage = async (messageData) => {
        try {
            console.log('sendHttpMessage called with:', messageData);

            const authToken = getAuthToken();
            if (!authToken) {
                console.error('No auth token available');
                return {
                    success: false,
                    error: 'Authentication token missing'
                };
            }

            // FIX: Create proper payload with ALL required fields
            const payload = {
                sender_id: messageData.sender_id,
                receiver_id: messageData.receiver_id,
                content: messageData.content || "", // Always include content
                encrypted_content: messageData.encrypted_content || {}, // Always include encrypted_content
                timestamp: new Date().toISOString()
            };

            // Add file data if it exists
            if (messageData.file) {
                payload.file = messageData.file;
            }

            // Add encryption info if it exists
            if (messageData.encryption) {
                payload.encryption = messageData.encryption;
            }

            console.log('Final payload to send:', payload);

            const response = await fetch(`${API_CONFIG.BASE_URL}/api/send-message`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${authToken}`
                },
                body: JSON.stringify(payload)
            });

            console.log('Send message response status:', response.status);

            if (response.ok) {
                const result = await response.json();
                console.log('Message sent successfully:', result);
                return {
                    success: true,
                    result: result
                };
            } else {
                console.error('Send message failed with status:', response.status);
                const errorText = await response.text();
                console.error('Error response:', errorText);
                
                return {
                    success: false,
                    error: `Server error: ${response.status} - ${errorText}`
                };
            }
        } catch (error) {
            console.error('Network error sending message:', error);
            return {
                success: false,
                error: `Network error: ${error.message}`
            };
        }
    };

    const sendDecodeErrorMessage = async () => {
        console.log('Sending decode error message to sender');
        
        const messageData = {
            id: Date.now() + Math.random(), // Ensure unique ID
            sender: 'you',
            sender_id: currentUser?.id || currentUser?._id,
            receiver_id: targetUser?.id || targetUser?._id,
            content: 'Message decode unsuccessful, please re-encode message and send',
            timestamp: new Date().toISOString()
        };

        // Try WebSocket first, then fallback to HTTP
        const sent = sendWebSocketMessage({
            type: 'message',
            message: messageData
        });

        if (!sent) {
            await sendHttpMessage(messageData);
        }
    };

    const formatTime = (timestamp) => {
        if (!timestamp) return '';

        try {
            const date = new Date(timestamp);
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } catch (error) {
            console.error('Error formatting time:', error);
            return '';
        }
    };

    const handleDownload = (file) => {
        if (!file || !file.url) {
            console.error('Invalid file object for download');
            return;
        }

        try {
            // Create a temporary anchor element to trigger download
            const link = document.createElement('a');
            link.href = file.url;
            link.download = file.name || 'download';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } catch (error) {
            console.error('Error downloading file:', error);
            alert('Failed to download file');
        }
    };

    // Add these handler functions in your component (place them with your other handler functions)
    const handleDeleteClick = useCallback((message) => {
        console.log('️Delete button clicked for message:', message.id);
        stopHttpPolling();
        setIsUserInteracting(true);
        setMessageToDelete(message);
        setDeleteModalOpen(true);
        setActiveMenu(null); 
    }, []);

    const handleConfirmDelete = useCallback(async () => {
        if (!messageToDelete) return;

        try {
            setIsDeleting(true);
            setIsUserInteracting(true);
            
            // Your existing delete logic...
            const authToken = getAuthToken();
            if (!authToken) {
                throw new Error('Authentication token missing');
            }

            const response = await fetch(`${API_CONFIG.BASE_URL}/api/messages/${messageToDelete.id}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Delete failed: ${response.status} - ${errorText}`);
            }

            const result = await response.json();
            console.log('Message deleted successfully:', result);

            // Remove the message from local state
            setMessages(prev => prev.filter(msg => msg.id !== messageToDelete.id));
            
            // Close modal and reset state
            setDeleteModalOpen(false);
            setMessageToDelete(null);
            setActiveMenu(null); 
            
            // alert('Message deleted successfully');
            
        } catch (error) {
            console.error('Delete failed:', error);
            alert(`Failed to delete message: ${error.message}`);
        } finally {
            setIsDeleting(false);
        }
    }, [messageToDelete]);

    const handleCancelDelete = useCallback(() => {
        setDeleteModalOpen(false);
        setMessageToDelete(null);
        setActiveMenu(null);
    }, []);

    // Handle menu click
    const handleMenuClick = useCallback((message, event) => {
        event.stopPropagation();
        setActiveMenu(activeMenu === message.id ? null : message.id);
    }, [activeMenu]);

    // Handle copy message
    const handleCopyMessage = useCallback(async (message) => {
        try {
            const textToCopy = message.decryptedContent || message.content || '';
            if (textToCopy) {
                await navigator.clipboard.writeText(textToCopy);
                alert('Message copied to clipboard!');
            } else {
                alert('No text content to copy');
            }
        } catch (error) {
            console.error('Failed to copy message:', error);
            alert('Failed to copy message');
        }
    }, []);

    // Close menu when clicking outside
    useEffect(() => {
        const handleClickOutside = (event) => {
            if (menuRef.current && !menuRef.current.contains(event.target)) {
                setActiveMenu(null);
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, []);

    const renderMessages = () => {
        console.log('Rendering messages:', messages.length, 'messages');

        if (!messages || messages.length === 0) {
            return (
                <div className="no-messages">
                    <i className="fas fa-comments"></i>
                    <p>No messages yet. Start a conversation!</p>
                </div>
            );
        }

        return messages.map((msg) => {
            const senderId = msg.sender_id || msg.senderId || msg.sender;
            const normalizedSenderId = normalizeUserId(senderId);
            const normalizedCurrentUserId = normalizeUserId(currentUser?.id || currentUser?._id);
            const isCurrentUser = normalizedSenderId === normalizedCurrentUserId;

            const isEncrypted = msg.encryption?.enabled || msg.encrypted_content;
            const isTextMessage = msg.message_type === 'text' || (!msg.file && !msg.message_type);
            const isFileMessage = msg.file && msg.file.url;
            const isSending = msg.status === 'sending';

            let displayContent = '';

            // Handle different message states
            if (isSending) {
                displayContent = '';
            }
            else if (msg.status === 'failed') {
                displayContent = 'Failed to send';
            }
            else if (isTextMessage) {
                if (msg.decryptedContent) {
                    displayContent = msg.decryptedContent;
                } else if (msg.content && msg.content.trim() !== '') {
                    displayContent = msg.content;
                } else if (msg.encrypted_content && Object.keys(msg.encrypted_content).length > 0) {
                    displayContent = 'Encrypted message...';
                } else {
                    displayContent = '[Message]';
                }
            }
            else if (isFileMessage && msg.content && msg.content.trim() !== '') {
                displayContent = msg.content;
            }

            return (
                <div
                    key={msg.id || msg._id || `msg-${Date.now()}`}
                    className={`message ${isCurrentUser ? 'you' : 'other'} ${msg.status || 'sent'}`}
                >
                    <div className="message-content">
                        {/* Show status indicators */}
                        {isSending && (
                            <div className="message-status sending">
                                <i className="fas fa-clock"></i>
                                <span>Sending...</span>
                            </div>
                        )}
                        
                        {msg.status === 'failed' && (
                            <div className="message-status failed">
                                <i className="fas fa-exclamation-triangle"></i>
                                <span>Failed to send</span>
                            </div>
                        )}

                        {/* Show sender name for other users */}
                        {!isCurrentUser && (
                            <div className="message-sender">
                                {targetUser?.username || 'Unknown User'}
                            </div>
                        )}

                        {/* Show file preview only if NOT during sending status */}
                        {isFileMessage && !isSending && (
                            <div className="message-file">
                                <div
                                    className="file-preview clickable-media"
                                    onClick={() => handleMediaClick(msg.file)}
                                    style={{ cursor: 'pointer' }}
                                >
                                    {msg.file.type === 'image' ? (
                                        <img
                                            src={msg.file.url || msg.file.stego_url}
                                            alt={msg.file.name}
                                            onError={(e) => {
                                                e.target.src = 'https://via.placeholder.com/150?text=Image+Error';
                                            }}
                                        />
                                    ) : msg.file.type === 'audio' ? (
                                        <div className="audio-preview">
                                            <i className="fas fa-volume-up"></i>
                                            <span>Audio Message</span>
                                            <div className="play-indicator">
                                                <i className="fas fa-play"></i>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="file-preview-generic">
                                            <i className="fas fa-file"></i>
                                            <span>File Attachment</span>
                                        </div>
                                    )}
                                </div>
                                <div className="file-actions">
                                    <span className="file-name">{msg.file.name}</span>
                                    {msg.file.is_encrypted && (
                                        <span className="file-encryption-badge">
                                            <i className="fas fa-lock"></i>
                                        </span>
                                    )}
                                    {/* Download button for received files */}
                                    {!isCurrentUser && msg.file && (
                                        <button
                                            className="download-btn"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                handleDownload(msg.file);
                                            }}
                                            title="Download file"
                                        >
                                            <i className="fas fa-download"></i>
                                        </button>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Show file preview placeholder during sending status */}
                        {isFileMessage && isSending && (
                            <div className="message-file">
                                <div className="file-preview file-preview-sending">
                                    {msg.file.type === 'image' ? (
                                        <div className="file-preview-sending-placeholder">
                                            <i className="fas fa-image"></i>
                                            <span>Uploading image...</span>
                                        </div>
                                    ) : msg.file.type === 'audio' ? (
                                        <div className="file-preview-sending-placeholder">
                                            <i className="fas fa-volume-up"></i>
                                            <span>Uploading audio...</span>
                                        </div>
                                    ) : (
                                        <div className="file-preview-sending-placeholder">
                                            <i className="fas fa-file"></i>
                                            <span>Uploading file...</span>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Show text content only if it exists and NOT during sending status */}
                        {displayContent && displayContent.trim() !== '' && !isSending && (
                            <div className="message-text">
                                {displayContent}
                                {/* Show encryption badge for encrypted text messages */}
                                {isEncrypted && isTextMessage && (
                                    <span className="encryption-badge" title="Encrypted message">
                                        <i className="fas fa-lock"></i>
                                    </span>
                                )}
                            </div>
                        )}

                        {/* WhatsApp-style menu button - ONLY FOR SENDER */}
                        {isCurrentUser && (
                            <div className="message-menu">
                                <button
                                    className="menu-btn"
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        handleMenuClick(msg, e);
                                    }}
                                    title="Message options">
                                    <i className="fas fa-ellipsis-v"></i>
                                </button>
                                
                                {/* Dropdown menu */}
                                {activeMenu === msg.id && (
                                    <div className="message-dropdown" ref={menuRef}>
                                        <button
                                            className="dropdown-item delete-item"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                handleDeleteClick(msg);
                                                setActiveMenu(null);
                                            }}>
                                            <i className="fas fa-trash"></i>
                                            Delete Message
                                        </button>
                                        {msg.file && (
                                            <button
                                                className="dropdown-item"
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    handleDownload(msg.file);
                                                    setActiveMenu(null);
                                                }}>
                                                <i className="fas fa-download"></i>
                                                Download File
                                            </button>
                                        )}
                                    </div>
                                )}
                            </div>
                        )}

                        <div className="message-time">
                            {formatTime(msg.timestamp)}
                            {isSending && ' • Sending...'}
                            {msg.status === 'failed' && ' • Failed'}
                        </div>
                    </div>
                </div>
            );
        });
    };

    const DeleteConfirmationModal = ({ isOpen, onClose, onConfirm, message, isDeleting }) => {
        if (!isOpen) return null;

        return (
            <div className="modal-overlay">
                <div className="delete-confirmation-modal">
                    <div className="modal-header">
                        <i className="fas fa-exclamation-triangle warning-icon"></i>
                        <h3>Delete Message</h3>
                    </div>
                    
                    <div className="modal-body">
                        <p>Are you sure you want to delete this message?</p>
                        {message?.file && (
                            <div className="file-preview-delete">
                                {message.file.type === 'image' ? (
                                    <img 
                                        src={message.file.url} 
                                        alt="To be deleted" 
                                        className="preview-image"
                                    />
                                ) : message.file.type === 'audio' ? (
                                    <div className="audio-preview-delete">
                                        <i className="fas fa-volume-up"></i>
                                        <span>Audio File</span>
                                    </div>
                                ) : (
                                    <div className="file-preview-delete">
                                        <i className="fas fa-file"></i>
                                        <span>{message.file.name}</span>
                                    </div>
                                )}
                            </div>
                        )}
                        <p className="warning-text">
                            This action cannot be undone. The message will be permanently deleted.
                        </p>
                    </div>
                    
                    <div className="modal-actions">
                        <button 
                            className="cancel-btn"
                            onClick={onClose}
                            disabled={isDeleting}>
                            Cancel
                        </button>
                        <button 
                            className="confirm-delete-btn"
                            onClick={onConfirm}
                            disabled={isDeleting}>
                            {isDeleting ? (
                                <>
                                    <div className="spinner-small"></div>
                                    Deleting...
                                </>
                            ) : (
                                <>
                                    <i className="fas fa-trash"></i>
                                    Delete
                                </>
                            )}
                        </button>
                    </div>
                </div>
            </div>
        );
    };

    //the message decryption useEffect
    useEffect(() => {
        const decryptMessages = async () => {
            if (!messages.length || !isE2EEEnabled || !e2eeAPI.isReady()) return;

            let hasUpdates = false;
            const updatedMessages = [];

            for (const msg of messages) {
                // Skip if already decrypted or not a text message with encrypted content
                if (msg.decryptedContent || 
                    !msg.encrypted_content || 
                    Object.keys(msg.encrypted_content).length === 0 ||
                    (msg.file && !msg.content)) { // Skip file messages without additional text
                    updatedMessages.push(msg);
                    continue;
                }

                try {
                    console.log('Attempting to decrypt message:', msg.id);
                    const decrypted = await e2eeAPI.decryptMessage(msg.encrypted_content, msg.sender_id);
                    console.log('Successfully decrypted message:', decrypted);
                    updatedMessages.push({ ...msg, decryptedContent: decrypted });
                    hasUpdates = true;
                } catch (error) {
                    console.warn('Failed to decrypt message:', error);
                    // Keep the original encrypted content but mark as undecryptable
                    updatedMessages.push({ ...msg, decryptedContent: 'Unable to decrypt message' });
                    hasUpdates = true;
                }
            }

            // Only update if messages actually changed
            if (hasUpdates) {
                console.log('Updating messages with decrypted content');
                setMessages(updatedMessages);
            }
        };

        decryptMessages();
    }, [messages, isE2EEEnabled]);

    // Then fetch messages for that user
    useEffect(() => {
        if (selectedChatPartner) {
            fetchMessages(selectedChatPartner.id);
        }
    }, [selectedChatPartner]);

    useEffect(() => {
        const updateCharLimit = async () => {
            if (operationMode === 'encode' && selectedFile) {
                const limit = await calculateMaxCharCapacity(selectedFile, fileType);
                setMaxCharLimit(limit);
                
                // Set informative message about capacity
                let infoMessage = '';
                if (fileType === 'image') {
                    infoMessage = `This image can hold up to ${limit} characters`;
                } else if (fileType === 'audio') {
                    infoMessage = `This audio file can hold up to ${limit} characters`;
                }
                setCharLimitInfo(infoMessage);
            } else if (operationMode === 'text') {
                setMaxCharLimit(1000); // Standard text message limit
                setCharLimitInfo('');
            } else if (operationMode === 'decode') {
                setMaxCharLimit(0); // No input for decode mode
                setCharLimitInfo('');
            }
        };
        updateCharLimit();
    }, [selectedFile, fileType, operationMode, calculateMaxCharCapacity]);

    // Update the handleFileSelect function to recalculate capacity
    const handleFileSelect = (e) => {
        const file = e.target.files[0];
            if (file) {
                setSelectedFile(file);
                const extension = file.name.split('.').pop().toLowerCase();
                    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'].includes(extension)) {
                        setFileType('image');
                    } else if (['wav', 'mp3', 'ogg', 'm4a', 'flac'].includes(extension)) {
                        setFileType('audio');
                    } 
                    else {
                        // Default to image if unknown type
                        setFileType('image');
                    }
            }
    };

    const handleKeyPress = useCallback((e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault(); // Prevent new line in textarea
            handleSend();
        }
    }, [handleSend]);

    useEffect(() => {
        const textarea = document.querySelector('.message-textarea');
        if (textarea) {
            textarea.addEventListener('keydown', handleKeyPress);
            return () => {
                textarea.removeEventListener('keydown', handleKeyPress);
            };
        }
    }, [handleKeyPress]);

    // Show error state
    if (error || !targetUser) {
        return (
            <div className="chat-window-error">
                <div className="chat-error">
                    <i className="fas fa-exclamation-triangle"></i>
                    <h3>Invalid Chat</h3>
                    <p>{error || 'No user selected or invalid user ID'}</p>
                    <button onClick={() => navigate('/dashboard')} className="return-button">
                        Return to Dashboard
                    </button>
                </div>
            </div>
        );
    }

    const debugE2EEStatus = () => {
        console.log(' E2EE COMPLETE STATUS CHECK:');
        console.log('isE2EEEnabled:', isE2EEEnabled);
        console.log('encryptionStatus:', encryptionStatus);
        console.log('encryptionService available:', !!encryptionService);
        console.log('currentUser ID:', currentUser?.id);
        console.log('targetUser ID:', targetUser?.id);
    };

    return (
        <div className="chat-window">
            <div className="chat-header">
                <button onClick={() => navigate(-1)} className="back-button">
                    <i className="fas fa-arrow-left"></i>
                </button>
                <h2>Chat with {targetUser.username || 'Unknown User'}</h2>
                {/* <div className="connection-status">
                    
                    <span className={`status-indicator ${connectionStatus}`}>
                        {connectionStatus === 'connected' && 'Online'}
                        {connectionStatus === 'polling' && 'Polling'}
                        {connectionStatus === 'disconnected' && 'Offline'}
                    </span>
                    
                    <span 
                        className={`e2ee-status ${encryptionStatus}`}
                        onClick={() => setShowEncryptionInfo(!showEncryptionInfo)}
                        title="Click for encryption info"
                    >
                        {encryptionStatus === 'active' && 'Encrypted'}
                        {encryptionStatus === 'unavailable' && 'No Encryption'}
                        {encryptionStatus === 'failed' && 'Encryption Failed'}
                        {encryptionStatus === 'checking' && 'Checking...'}
                    </span>
                </div>  */}
            </div>
                {showEncryptionInfo && (
                    <div className="encryption-info-tooltip">
                        <h4>End-to-End Encryption</h4>
                        <p>
                            {encryptionStatus === 'active' 
                                ? 'Your messages are encrypted and can only be read by you and the recipient.'
                                : encryptionStatus === 'unavailable'
                                ? 'Encryption is not available. Messages are sent in plaintext.'
                                : 'Encryption status is being checked...'
                            }
                        </p>
                        <button onClick={() => setShowEncryptionInfo(false)}>Close</button>
                    </div>
                )}
                
                <MediaPreviewModal media={selectedMedia} isOpen={isMediaModalOpen} onClose={() => { setIsMediaModalOpen(false); setSelectedMedia(null); }} />
            
                <DeleteConfirmationModal isOpen={deleteModalOpen}
                    onClose={handleCancelDelete}
                    onConfirm={handleConfirmDelete}
                    message={messageToDelete}
                    isDeleting={isDeleting} />
                
            <div ref={messagesContainerRef} className="messages-container" onScroll={handleScroll}>
                    {renderMessages()}
                    <div ref={messagesEndRef} style={{ height: '0px' }}/>
                    
                    {/* Scroll to bottom button */}
                    {showScrollToBottom && (
                        <button 
                            className="scroll-to-bottom-btn"
                            onClick={scrollToBottom}
                            title="Scroll to bottom"
                        >
                            <i className="fas fa-arrow-down"></i>
                        </button>
                    )}
                </div>
            
                <div className="chat-controls">
                    {/* Mode Selection */}
                    <div className="mode-selection">
                        <div className="mode-buttons">
                            {/* <button 
                                className={`mode-btn ${operationMode === 'text' ? 'active' : ''}`}
                                onClick={() => {
                                    setOperationMode('text');
                                    setMaxCharLimit(1000);
                                    setCharLimitInfo('Maximum 1000 characters for text messages');
                                }}>
                                <i className="fas fa-comment"></i>
                                Text
                            </button> */}
                            <button
                                className={`mode-btn ${operationMode === 'encode' ? 'active' : ''}`} onClick={() => setOperationMode('encode')}>
                                <i className="fas fa-lock"></i>
                                Encode
                            </button>
                            <button 
                                className={`mode-btn ${operationMode === 'decode' ? 'active' : ''}`}
                                onClick={() => {
                                    setOperationMode('decode');
                                    setMaxCharLimit(0);
                                    setCharLimitInfo('Decode mode - no character limit');
                                }}>
                                <i className="fas fa-unlock"></i>
                                Decode
                            </button>
                        </div>
                    </div>
                
                    {/* File Input (only shown for encode/decode modes) */}
                    {(operationMode === 'encode' || operationMode === 'decode') && (
                        <div className="file-input-section">
                            <div className="file-input-container">
                                <label className="file-input-label">
                                    <i className="fas fa-cloud-upload-alt"></i>
                                    <span>{selectedFile ? selectedFile.name : 'Select File'}</span>
                                    <input
                                        type="file"
                                        onChange={handleFileSelect}
                                        accept={
                                            fileType === 'image' ? '.jpg,.jpeg,.png,.gif,.bmp,.webp' :
                                            fileType === 'audio' ? '.wav,.mp3,.ogg,.m4a,.flac' :
                                            '.mp4,.mov,.avi,.webm,.mkv'
                                        }
                                        style={{ display: 'none' }}
                                    />
                                </label>
                                
                                <select
                                    value={fileType}
                                    onChange={async (e) => {
                                        setFileType(e.target.value);
                                        if (selectedFile) {
                                            const limit = await calculateMaxCharCapacity(selectedFile, e.target.value);
                                            setMaxCharLimit(limit);
                                        }
                                    }}
                                    className="file-type-select"
                                >
                                    <option value="image">Image(PNG/JPG)</option>
                                    <option value="audio">Audio(WAV)</option>
                                </select>
                            </div>
                            
                            {selectedFile && (
                                <div className="file-preview-mini">
                                    {fileType === 'image' ? (
                                    <img src={URL.createObjectURL(selectedFile)} alt="Preview" />
                                    ) : fileType === 'audio' ? (
                                    <div className="audio-preview-mini">
                                        <i className="fas fa-volume-up"></i>
                                        <span>Audio File</span>
                                    </div>
                                    ) : null}
                                </div>
                                )
                            }

                        </div>
                    )}

                    {/* Message Input */}
                    <div className="message-input-section">
                        <div className="input-header">
                            <span>
                                {operationMode === 'text' ? 'Your message' :
                                operationMode === 'encode' ? 'Secret message to hide' :
                                'Decoded message'}
                            </span>
                            {operationMode !== 'decode' && (
                                <span className={`char-count ${message.length > maxCharLimit * 0.9 ? 'char-warning' : ''}`}>
                                    {message.length}/{maxCharLimit}
                                </span>
                            )}
                        </div>
                        
                        <div className="input-container">
                            <textarea
                                value={message}
                                onChange={handleMessageChange}
                                onKeyDown={handleKeyPress}
                                placeholder={
                                    operationMode === 'text' ? 'Type your message here...' :
                                    operationMode === 'encode' ? 'Enter your secret message to hide in the file...' :
                                    'Decoded message will appear here...'
                                }
                                disabled={operationMode === 'decode'}
                                className="message-textarea"
                                maxLength={operationMode !== 'decode' ? maxCharLimit : undefined}
                                rows={3}
                            />
                        </div>
                    </div>

                    {/* Send Controls */}
                    <div className="send-controls">
                        <div className="status-info">
                            {isProcessing && (
                                <div className="processing-indicator">
                                    <div className="spinner"></div>
                                    <span>
                                        {operationMode === 'encode' ? 'Encoding...' :
                                        operationMode === 'decode' ? 'Decoding...' :
                                        'Sending...'}
                                    </span>
                                </div>
                            )}
                        </div>
                        
                        <button
                            onClick={handleSend}
                            disabled={isProcessing || 
                                    (operationMode === 'encode' && (!message || !selectedFile)) || 
                                    (operationMode === 'text' && !message.trim()) ||
                                    (operationMode === 'decode' && !selectedFile)}
                            className="send-button"
                        >
                            {operationMode === 'text' ? (
                                <>
                                    <i className="fas fa-paper-plane"></i>
                                    Send
                                </>
                            ) : operationMode === 'encode' ? (
                                <>
                                    <i className="fas fa-lock"></i>
                                    Encode & Send
                                </>
                            ) : (
                                <>
                                    <i className="fas fa-unlock"></i>
                                    Decode
                                </>
                            )}
                        </button>
                    </div>
            </div>
        </div>
    );
};

export default ChatWindow;