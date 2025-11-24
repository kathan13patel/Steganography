import React, { useState, useEffect } from 'react';
import { useAuth } from '../../services/auth';

const EditProfile = () => {
  const { user } = useAuth();
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    mobile: '',
    profileImage: null
  });
  const [previewImage, setPreviewImage] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (user) {
      setFormData({
        username: user.username || '',
        email: user.email || '',
        mobile: user.mobile || '',
        profileImage: null
      });
    }
  }, [user]);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setFormData({ ...formData, profileImage: file });
      setPreviewImage(URL.createObjectURL(file));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage('Profile updated successfully!');
    // Here you would make API call to update profile
  };

  return (
    <div className="profile-edit">
      <h2>Edit Profile</h2>
      
      {message && <div className="success-message">{message}</div>}

      <form onSubmit={handleSubmit} className="profile-form">
        <div className="profile-image-section">
          <div className="image-preview">
            <img
              src={previewImage || '/default-avatar.png'}
              alt="Profile Preview"
              className="profile-preview"
            />
          </div>
          <input
            type="file"
            accept="image/*"
            onChange={handleImageChange}
            className="image-upload"
          />
        </div>

        <div className="form-group">
          <label>Username:</label>
          <input
            type="text"
            name="username"
            value={formData.username}
            onChange={handleChange}
            required
          />
        </div>

        <div className="form-group">
          <label>Email:</label>
          <input
            type="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            required
          />
        </div>

        <div className="form-group">
          <label>Mobile:</label>
          <input
            type="tel"
            name="mobile"
            value={formData.mobile}
            onChange={handleChange}
          />
        </div>

        <button type="submit" className="save-button">
          Save Changes
        </button>
      </form>
    </div>
  );
};

export default EditProfile;