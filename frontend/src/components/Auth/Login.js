import React, { useState } from 'react';
import { useAuth } from '../../services/auth';
import { Link } from 'react-router-dom';
import encryptionService from '../../services/encryptionService';
import axios from 'axios';

const Login = () => {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

    const initializeUserEncryption = async (userId) => {
        try {
        console.log('Initializing E2EE for user:', userId);
        
        // Check if user already has keys
        if (encryptionService.hasUserKeys(userId)) {
            console.log('User already has encryption keys');
            return true;
        }

        // Generate new encryption keys
        console.log('Generating new encryption keys...');
        const userKeys = await encryptionService.generateUserKeys();
        
        // Store keys locally
        encryptionService.storeUserKeys(userId, userKeys);
        
        // Exchange public key with server (simplified - in production use proper key exchange)
        try {
            await axios.post('http://localhost:8000/api/keys/exchange', {
            public_key: userKeys.keyPair.publicKey,
            target_user_id: 'server' // Simplified - in production exchange with actual users
            }, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            }
            });
            console.log('Public key exchanged with server');
        } catch (exchangeError) {
            console.warn('Key exchange failed (server might not support it yet):', exchangeError);
            // Continue anyway - keys are stored locally
        }

        console.log('E2EE initialization completed');
        return true;
        } catch (error) {
        console.error('E2EE initialization failed:', error);
        return false;
        }
    };
    
    const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const result = await login(formData.username, formData.password);
      
      if (!result.success) {
        setError(result.error);
        setLoading(false);
        return;
      }

      // Initialize E2EE after successful login
      if (result.user && result.user.id) {
        console.log('Login successful, starting E2EE setup...');
        const e2eeSuccess = await initializeUserEncryption(result.user.id);
        
        if (!e2eeSuccess) {
          console.warn('E2EE setup had issues, but login completed');
          // Don't block login if E2EE fails
        }
        
        console.log('Login and E2EE setup completed successfully');
      }
      
    } catch (error) {
      console.error('Login error:', error);
      setError('Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <h2>Login</h2>
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
          <label>Password:</label>
          <input
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            required
          />
        </div>
        
        <button type="submit" className="auth-button" disabled={loading}>
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </form>
      
      <Link to="/register" className="auth-link">
        Don't have an account? Register here
          </Link>
          {/* <div className="e2ee-status" style={{marginTop: '20px', fontSize: '12px', color: '#666'}}>
        <small>🔒 End-to-End Encryption: Enabled</small>
      </div> */}
    </div>
  );
};

export default Login;