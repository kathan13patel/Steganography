import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../services/auth';
import './css/Profile.css';

const ProfilePage = () => {
  const [user, setUser] = useState({
    username: '',
    email: '',
    mobile: '',
    profile_image: 'default.png',
    created_at: ''
  });
  const navigate = useNavigate();
  const {logout, token, isAuthenticated } = useAuth();
  const [originalUser, setOriginalUser] = useState({});
  const [isEditing, setIsEditing] = useState(false);
  const [changePassword, setChangePassword] = useState(false);
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
    const [uploadingImage, setUploadingImage] = useState(false);
    useEffect(() => {
  if (!loading && !isAuthenticated) {
    navigate('/login');
  }
}, [loading, isAuthenticated, navigate]);
        
  // Fetch user data from backend
  useEffect(() => {
    if (isAuthenticated && token) {
        fetchUserData();
    }
    }, [isAuthenticated, token]);

  const fetchUserData = async () => {
    try {
        setLoading(true);
        if (!token) {
        setMessage('Authentication token missing');
        return;
        }

    console.log('Fetching profile with token:', token.substring(0, 20) + '...');

    const response = await fetch('http://localhost:8000/api/profile', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

        if (response.ok) {
            const userData = await response.json();
            setUser(userData);
            setOriginalUser(userData);
        }else if (response.status === 401) {
        setMessage('Session expired. Please log in again.');
        logout();
        } else {
        const errorData = await response.json().catch(() => ({}));
        setMessage(errorData.error || 'Error loading profile data');
        }
    } catch (error) {
      setMessage('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setUser(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handlePasswordChange = (e) => {
    const { name, value } = e.target;
    setPasswordData(prev => ({
      ...prev,
      [name]: value
    }));
    };
    
const handleImageUpload = async (e) => {
  const file = e.target.files[0];
  if (!file) return;

  const validTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
  if (!validTypes.includes(file.type)) {
    setMessage('Invalid file type. Please select a JPG, PNG, or GIF image.');
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    setMessage('File size too large. Please select an image under 5MB.');
    return;
  }

  // Instant preview
  const previewURL = URL.createObjectURL(file);
  setUser(prev => ({
    ...prev,
    profile_image: previewURL
  }));

  setUploadingImage(true);
  setMessage('');

  try {
    if (!token) {
    setMessage('Authentication token missing');
    return;
    }

    const formData = new FormData();
    formData.append('image', file);

    const response = await fetch('http://localhost:8000/api/profile/upload-image', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
      body: formData
    });

    const data = await response.json();

    if (response.ok) {
      setMessage('Profile image updated successfully!');
      // Update with real server path after upload
      setUser(prev => ({
        ...prev,
        profile_image: data.filename
      }));
    } else {
      setMessage(data.message || 'Error uploading image');
    }
  } catch (error) {
    console.error('Upload error:', error);
    setMessage('Network error. Please try again.');
  } finally {
    setUploadingImage(false);
  }
};

  const handleSaveProfile = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
        if (!token) {
        setMessage('Authentication token missing');
        return;
        }

        const response = await fetch('http://localhost:8000/api/profile/update', {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(user)
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('Profile updated successfully!');
        setIsEditing(false);
        setOriginalUser(user);
      } else {
        setMessage(data.message || 'Error updating profile');
      }
    } catch (error) {
      setMessage('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setMessage('New passwords do not match');
      return;
    }

    if (passwordData.newPassword.length < 6) {
      setMessage('Password must be at least 6 characters long');
      return;
    }

    setLoading(true);

    try {
        if (!token) {
    setMessage('Authentication token missing');
    return;
    }
    const response = await fetch('http://localhost:8000/api/profile/change-password', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          currentPassword: passwordData.currentPassword,
          newPassword: passwordData.newPassword
        })
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('Password changed successfully!');
        setChangePassword(false);
        setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
      } else {
        setMessage(data.message || 'Error changing password');
      }
    } catch (error) {
      setMessage('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleCancelEdit = () => {
    setUser(originalUser);
    setIsEditing(false);
    setMessage('');
  };

  const handleCancelPassword = () => {
    setChangePassword(false);
    setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
    setMessage('');
  };

  const handleDeleteAccount = async () => {
    if (!window.confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
      return;
    }

    try {
    if (!token) {
    setMessage('Authentication token missing');
    return;
    }
      const response = await fetch('http://localhost:8000/api/profile/delete', {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        logout();
        navigate('/login');
      } else {
        setMessage('Error deleting account');
      }
    } catch (error) {
      setMessage('Network error. Please try again.');
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="profile-container">
      <div className="profile-header">
        <h1>Profile Management</h1>
        <p>Manage your account settings and preferences</p>
      </div>

      {message && (
        <div className={`message ${message.includes('Error') ? 'error' : 'success'}`}>
          {message}
          <button 
            className="message-close"
            onClick={() => setMessage('')}
          >
            ×
          </button>
        </div>
      )}

      <div className="profile-content">
        {/* Profile Image Section */}
        <div className="profile-section profile-image-section">
          <h2>Profile Picture</h2>
          <div className="image-container">
            <img 
              src={
                !user.profile_image || user.profile_image === 'default.png'
                  ? '/profile.jpg'
                  : user.profile_image.startsWith('blob:')
                    ? user.profile_image
                    : `http://localhost:8000/uploads/profile_images/${user.profile_image}`
              }
              alt="Profile"
              className="profile-image"
              onError={(e) => {
                e.target.src = '/profile.jpg';
              }}
            />
            <div className="image-actions">
              <label htmlFor="image-upload" className="upload-btn">
                {uploadingImage ? 'Uploading...' : 'Change Picture'}
              </label>
              <input
                id="image-upload"
                type="file"
                accept="image/jpeg, image/jpg, image/png, image/gif"
                onChange={handleImageUpload}
                disabled={uploadingImage}
                style={{ display: 'none' }}
              />
              {user.profile_image !== 'default.png' && (
                <button 
                  className="remove-btn"
                  onClick={() => {
                    // Implement remove image functionality
                    setMessage('Image removal not implemented yet');
                  }}
                  disabled={uploadingImage}
                >
                  Remove Picture
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Profile Information Section */}
        <div className="profile-section">
          <div className="section-header">
            <h2>Personal Information</h2>
            {!isEditing && (
              <button 
                className="edit-btn"
                onClick={() => setIsEditing(true)}
                disabled={loading}
              >
                Edit Profile
              </button>
            )}
          </div>

          <form onSubmit={handleSaveProfile}>
            <div className="form-group">
              <label>Username</label>
              <input
                type="text"
                name="username"
                value={user.username}
                onChange={handleInputChange}
                disabled={!isEditing || loading}
                required
                pattern="[A-Za-z0-9_]{3,20}"
                title="Username must be 3-20 characters (letters, numbers, underscore)"
              />
            </div>

            <div className="form-group">
              <label>Email Address</label>
              <input
                type="email"
                name="email"
                value={user.email}
                onChange={handleInputChange}
                disabled={!isEditing || loading}
                required
              />
            </div>

            <div className="form-group">
              <label>Mobile Number</label>
              <input
                type="tel"
                name="mobile"
                value={user.mobile}
                onChange={handleInputChange}
                disabled={!isEditing || loading}
                required
                pattern="[0-9]{10}"
                title="Please enter a valid 10-digit mobile number"
              />
            </div>

            {isEditing && (
              <div className="form-actions">
                <button 
                  type="submit" 
                  className="save-btn"
                  disabled={loading}
                >
                  {loading ? 'Saving...' : 'Save Changes'}
                </button>
                <button 
                  type="button" 
                  className="cancel-btn"
                  onClick={handleCancelEdit}
                  disabled={loading}
                >
                  Cancel
                </button>
              </div>
            )}
          </form>
        </div>

        {/* Password Change Section */}
        <div className="profile-section">
          <div className="section-header">
            <h2>Security</h2>
            {!changePassword && (
              <button 
                className="change-password-btn"
                onClick={() => setChangePassword(true)}
                disabled={loading}
              >
                Change Password
              </button>
            )}
          </div>

          {changePassword && (
            <form onSubmit={handleChangePassword}>
              <div className="form-group">
                <label>Current Password</label>
                <input
                  type="password"
                  name="currentPassword"
                  value={passwordData.currentPassword}
                  onChange={handlePasswordChange}
                  required
                disabled={loading}
                placeholder="At least 6 characters"
                />
              </div>

              <div className="form-group">
                <label>New Password</label>
                <input
                  type="password"
                  name="newPassword"
                  value={passwordData.newPassword}
                  onChange={handlePasswordChange}
                  required
                  minLength={6}
                  disabled={loading}
                  placeholder="At least 6 characters"
                />
              </div>

              <div className="form-group">
                <label>Confirm New Password</label>
                <input
                  type="password"
                  name="confirmPassword"
                  value={passwordData.confirmPassword}
                  onChange={handlePasswordChange}
                required
                disabled={loading}
                placeholder="At least 6 characters"
                />
              </div>

              <div className="form-actions">
                <button 
                  type="submit" 
                  className="save-btn"
                  disabled={loading}
                >
                  {loading ? 'Updating...' : 'Update Password'}
                </button>
                <button 
                  type="button" 
                  className="cancel-btn"
                  onClick={handleCancelPassword}
                  disabled={loading}
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>

        {/* Additional Features */}
        <div className="profile-section">
          <h2>Account Actions</h2>
          <div className="account-actions">
            <button 
              className="action-btn danger"
              onClick={handleDeleteAccount}
              disabled={loading}
            >
              Delete Account
            </button>
            <button 
              className="action-btn"
              onClick={handleLogout}
            >
              Logout
            </button>
          </div>
        </div>

        {/* Session Information */}
        <div className="profile-section">
            <h2>Session Information</h2>
            <div className="session-info">
                <p><strong>Last Login:</strong> {new Date().toLocaleDateString('en-GB')}</p>
                <p><strong>Account Created:</strong> {user?.created_at ? new Date(user.created_at).toLocaleDateString('en-GB') : 'Loading...'}</p>
            </div>
        </div>
              
        <div className="profile-actions" style={{ marginTop: '20px' }}>
            <Link 
            to="/dashboard"
            className="btn btn-primary"
            style={{
                display: 'inline-block',
                padding: '10px 20px',
                backgroundColor: '#007bff',
                color: 'white',
                textDecoration: 'none',
                borderRadius: '5px',
                cursor: 'pointer',
                fontSize: '16px',
                textAlign: 'center'
            }}
            >
            <i className="fas fa-home" style={{ marginRight: '8px' }}></i>
            Back to Home
            </Link>
        </div>
      </div>
    </div>
  );
};

export default ProfilePage;