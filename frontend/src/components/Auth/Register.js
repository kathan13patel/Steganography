import React, { useState } from 'react';
import { useAuth } from '../../services/auth';
import { Link, useNavigate } from 'react-router-dom';
import encryptionService from '../../services/encryptionService';
import axios from 'axios';

const Register = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    mobile: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const authContext = useAuth();
  const navigate = useNavigate();

  // Destructure the register function
  const { register } = authContext;

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const initializeUserEncryption = async (userId) => {
    try {
      console.log('🔑 Initializing E2EE for new user:', userId);
      
      // Generate cryptographic keys for the new user
      console.log('🔑 Generating cryptographic keys...');
      const userKeys = await encryptionService.generateUserKeys();
      
      // Store keys locally
      encryptionService.storeUserKeys(userId, userKeys);
      
      // Get encryption status
      const status = encryptionService.getEncryptionStatus(userId);
      console.log('E2EE initialized for new user:', status);

      // Exchange public key with server
      try {
        await axios.post('http://localhost:8000/api/keys/exchange', {
          public_key: userKeys.keyPair.publicKey,
          target_user_id: 'server',
          key_id: userKeys.keyId,
          is_fallback: userKeys.isFallback || false
        }, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
            'Content-Type': 'application/json'
          }
        });
        console.log('Public key exchanged with server during registration');
      } catch (exchangeError) {
        console.warn('Key exchange failed during registration:', exchangeError);
        // Continue anyway - keys are stored locally
      }

      return true;
    } catch (error) {
      console.error('E2EE initialization failed during registration:', error);
      return false;
    }
  };
    
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    // Validation
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    if (formData.password.length < 6) {
      setError('Password must be at least 6 characters long');
      setLoading(false);
      return;
    }

    try {
      const result = await register(formData);

      if (result.success) {
        console.log('Registration successful, setting up E2EE...');
        
        // ADD THIS: Initialize E2EE after successful registration
        if (result.user && result.user.id) {
          const e2eeSuccess = await initializeUserEncryption(result.user.id);
          
          if (e2eeSuccess) {
            console.log('Registration and E2EE setup completed successfully');
            
            // Show success message with E2EE info
            const status = encryptionService.getEncryptionStatus(result.user.id);
            console.log('E2EE Status:', status);
            navigate('/login');
          } else {
            console.warn('E2EE setup failed, but registration completed');
            navigate('/login');
          }
        } else {
          // Fallback if user data is not available
          navigate('/login');
        }
      } else {
        // Handle error
        if (typeof result.error === 'string') {
          try {
            const errorData = JSON.parse(result.error);
            setError(errorData.error || 'Registration failed');
          } catch (parseError) {
            setError(result.error || 'Registration failed');
          }
        } else if (result.error?.error) {
          setError(result.error.error);
        } else {
          setError('Registration failed');
        }
      }
    } catch (error) {
      setError('An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <h2>Register</h2>
      {error && <div className="error-message">{error}</div>}
      
      <form onSubmit={handleSubmit} className="auth-form">
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
        
        <div className="form-group">
          <label>Password:</label>
          <input
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            required
            minLength="6"
          />
        </div>
        
        <div className="form-group">
          <label>Confirm Password:</label>
          <input
            type="password"
            name="confirmPassword"
            value={formData.confirmPassword}
            onChange={handleChange}
            required
            minLength="6"
          />
        </div>
        
        <button type="submit" className="auth-button" disabled={loading}>
          {loading ? 'Registering...' : 'Register'}
        </button>
      </form>
      
        <Link to="/login" className="auth-link">
            Already have an account? Login here
        </Link>
    </div>
  );
};

export default Register;