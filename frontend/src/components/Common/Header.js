import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../services/auth';
import UserSearch from './UserSearch';
import './css/Header.css';

const Header = () => {
    const TAB_ID = sessionStorage.getItem('tab_id') || crypto.randomUUID();
    sessionStorage.setItem('tab_id', TAB_ID);
    const getKey = (key) => `${TAB_ID}_${key}`;
    const { logout } = useAuth();
    const [authUser, setAuthUser] = useState(() => {
        const storedUser = localStorage.getItem(getKey('user')) || sessionStorage.getItem(getKey('user'));
        return storedUser ? JSON.parse(storedUser) : null;
    });
    const navigate = useNavigate();
    const location = useLocation();
    const [isMenuOpen, setIsMenuOpen] = useState(false);
    const [isSearchOpen, setIsSearchOpen] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');
    const [completeUser, setCompleteUser] = useState(null);
    const [imageError, setImageError] = useState(false);
    
    const handleLogin = () => {
        navigate('/login');
        setIsMenuOpen(false);
    };

    const handleRegister = () => {
        navigate('/register');
        setIsMenuOpen(false);
    };

  // Fetch complete user data if profile_image is missing from auth context
  useEffect(() => {
    const fetchCompleteUserData = async () => {
      // Only fetch if we have a user but no profile_image in auth context
      if (authUser?.id && (!authUser.profile_image || authUser.profile_image === 'undefined')) {
        try {
          const token = localStorage.getItem(getKey('token')) || sessionStorage.getItem(getKey('token'));
          const response = await fetch('http://localhost:8000/api/profile', {
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          });
          
          if (response.ok) {
            const userData = await response.json();
            setCompleteUser(userData);
          }
        } catch (error) {
          console.error('Failed to fetch user data:', error);
        }
      }
    };

    fetchCompleteUserData();
  }, [authUser]);

    useEffect(() => {
        const handleStorageChange = () => {
            const storedUser = localStorage.getItem(getKey('user'));
            if (storedUser) setAuthUser(JSON.parse(storedUser));
        };
        window.addEventListener('storage', handleStorageChange);
        return () => window.removeEventListener('storage', handleStorageChange);
    }, []);
    
  // Use completeUser if available, otherwise use the basic user from auth
  const currentUser = completeUser || authUser;

  const handleProfileClick = () => {
    navigate('/profile');
    setIsMenuOpen(false);
  };

  // Safe image URL calculation
  const getProfileImageUrl = () => {
    if (!currentUser?.profile_image) {
      return '/profile.jpg';
    }

    const profileImage = currentUser.profile_image;
    
    if (profileImage === 'undefined' || profileImage === 'null' || profileImage === 'default.png') {
      return '/profile.jpg';
    }
    
    if (profileImage.startsWith('blob:')) {
      return profileImage;
    }
    
    return `http://localhost:8000/uploads/profile_images/${currentUser.profile_image}`;

  };

  const handleImageError = (e) => {
    console.log('Image failed to load, falling back to default');
    setImageError(true);
    e.target.src = '/profile.jpg';
  };

  return (
    <>
      <header className="app-header">
        <div className="header-container">
          <Link to="/dashboard" className="logo">
            {!imageError ? (
          <img
            src="/logo.png"
            alt="StegoChat Logo"
            className="logo-img"
            onError={() => setImageError(true)}
          />
        ) : (
          <span className="fallback-text"></span>
        )}
            <span className="logo-text">StegoChat</span>
          </Link>

          <nav className={`nav-menu ${isMenuOpen ? 'nav-menu-open' : ''}`}>
            {/* Navigation items */}
          </nav>

          <div className="header-actions">
            {currentUser ? (
              <div className="user-menu">
                <div className="user-info" onClick={handleProfileClick} style={{cursor: 'pointer'}}>
                  {/* Show profile image if available and no error */}
                  {currentUser.profile_image && !imageError ? (
                    <img 
                      src={getProfileImageUrl()}
                      alt={currentUser.username || 'User'}
                      className="user-avatar"
                      onError={handleImageError}
                      onLoad={() => {
                        console.log('Profile image loaded successfully in header');
                      }}
                    />
                  ) : (
                    <div 
                      className="user-avatar user-avatar-fallback"
                      style={{
                        backgroundColor: '#007bff',
                        color: 'white',
                        borderRadius: '50%',
                        width: '40px',
                        height: '40px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: '16px',
                        fontWeight: 'bold'
                      }}
                    >
                      {currentUser.username?.charAt(0)?.toUpperCase() || 'U'}
                    </div>
                  )}
                </div>
              </div>
            ) : (
                <div className="auth-buttons">
                    <button onClick={handleLogin} className="btn btn-outline">
                        Login
                    </button>
                    <button onClick={handleRegister} className="btn btn-primary">
                        Register
                    </button>
                </div>
            )}
            
            <button 
              className="mobile-menu-toggle"
              onClick={() => setIsMenuOpen(!isMenuOpen)}>
              <span></span>
              <span></span>
              <span></span>
            </button>
          </div>
        </div>
      </header>

      {isSearchOpen && (
        <UserSearch 
          isOpen={isSearchOpen} 
          onClose={() => {
            setIsSearchOpen(false);
            setSearchTerm('');
          }}
          searchTerm={searchTerm}
        />
      )}
    </>
  );
};

export default Header;