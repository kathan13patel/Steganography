import React, { useState, useEffect } from 'react';
import { searchUsers } from '../../services/api';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../services/auth'; 
import './css/UserSearch.css';

const UserSearch = ({ isOpen, onClose, onStartChat }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [showLoginPrompt, setShowLoginPrompt] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const navigate = useNavigate();
  const { isAuthenticated, token } = useAuth(); 

  useEffect(() => {
    if (!isOpen) {
      setSearchTerm('');
      setSearchResults([]);
      setError('');
      setShowLoginPrompt(false);
      setSelectedUser(null);
      return;
    }
  }, [isOpen]);

  useEffect(() => {
    const delayDebounceFn = setTimeout(() => {
      if (searchTerm.trim().length > 0) {
        handleSearch();
      } else {
        setSearchResults([]);
      }
    }, 300);

    return () => clearTimeout(delayDebounceFn);
  }, [searchTerm]);

  const handleSearch = async () => {
    setIsLoading(true);
    setError('');
    
    try {
      const response = await searchUsers(searchTerm);
      if (response.success) {
        setSearchResults(response.users);
      } else {
        setError(response.message || 'Failed to search users');
      }
    } catch (err) {
      setError('An error occurred while searching');
      console.error('Search error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleUserSelect = (user) => {
    console.log('Selected user:', user);
    
    if (!user || !user.id) {
      console.error('Invalid user data for navigation:', user);
      return;
    }

    // If authenticated, proceed to chat
    navigateToChat(user);
  };

  const handleLogin = () => {
    // Navigate to login page with return URL and user info
    navigate('/login', { 
      state: { 
        returnTo: selectedUser ? `/chat/${selectedUser.id}` : '/dashboard',
        user: selectedUser // Pass the user data to pre-fill after login
      }
    });
    // REMOVE onClose() from here - let the navigation handle closing
  };

  const navigateToChat = (user) => {
    navigate(`/chat/${user.id}`, { 
      state: { 
        user: user
      }
    });
    onClose(); // Close modal only after successful navigation
  };

  const closeLoginPrompt = () => {
    setShowLoginPrompt(false);
    setSelectedUser(null);
  };

  if (!isOpen) return null;

  return (
    <div className="user-search-overlay" onClick={onClose}>
      <div className="user-search-modal" onClick={(e) => e.stopPropagation()}>
        <div className="user-search-header">
          <h3>Search Users</h3>
          <div className="header-buttons">
            <button className="exit-btn" onClick={onClose} title="Exit Search">
              <span>✕</span>
            </button>
          </div>
        </div>
        
        <div className="user-search-input">
          <i className="fas fa-search"></i>
          <input
            type="text"
            placeholder="Search by username..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            autoFocus
          />
        </div>
        
        <div className="user-search-results">
          {isLoading && (
            <div className="search-loading">
              <i className="fas fa-spinner fa-spin"></i>
              <span>Searching...</span>
            </div>
          )}
          
          {error && (
            <div className="search-error">
              <i className="fas fa-exclamation-circle"></i>
              <span>{error}</span>
            </div>
          )}
          
          {!isLoading && !error && searchResults.length === 0 && searchTerm.length > 0 && (
            <div className="no-results">
              <i className="fas fa-user-slash"></i>
              <span>No users found</span>
            </div>
          )}
          
          {!isLoading && !error && searchResults.length > 0 && (
            <div className="results-list">
              {searchResults.map(user => (
                <div 
                  key={user.id} 
                  className="user-result-item"
                  onClick={() => handleUserSelect(user)}
                >
                 <img 
                    src={
                        user.profile_image && user.profile_image !== 'default.png' 
                        ? `http://localhost:8000/uploads/profile_images/${user.profile_image}`
                        : '/profile.jpg'
                    } 
                    alt={user.username}
                    className="user-avatar"
                    onError={(e) => {
                        e.target.src = '/profile.jpg';
                    }}
                    />
                  <div className="user-info">
                    <span className="username">{user.username}</span>
                    {/* {!isAuthenticated && (
                      <span className="login-hint"></span>
                    )} */}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UserSearch;