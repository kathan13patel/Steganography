import React, { useState } from 'react';
import { useAuth } from '../../services/auth';
import Loader from '../Common/Loader';
import './css/Auth.css';

const AuthForm = ({ mode = 'login', onSwitchMode }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    mobile: ''
  });
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const { login, register } = useAuth();

  const validateForm = () => {
    const newErrors = {};

    // Username validation
    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    } else if (formData.username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters';
    } else if (!/^[a-zA-Z0-9_]+$/.test(formData.username)) {
      newErrors.username = 'Username can only contain letters, numbers, and underscores';
    }

    // Email validation (for register mode)
    if (mode === 'register') {
      if (!formData.email.trim()) {
        newErrors.email = 'Email is required';
      } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
        newErrors.email = 'Please enter a valid email address';
      }
    }

    // Password validation
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters';
    } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(formData.password)) {
      newErrors.password = 'Password must contain uppercase, lowercase, and numbers';
    }

    // Confirm password validation (for register mode)
    if (mode === 'register') {
      if (formData.password !== formData.confirmPassword) {
        newErrors.confirmPassword = 'Passwords do not match';
      }
    }

    // Mobile validation (optional)
    if (mode === 'register' && formData.mobile && !/^\+?[0-9]{10,15}$/.test(formData.mobile)) {
      newErrors.mobile = 'Please enter a valid mobile number';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));

    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setIsLoading(true);
    setErrors({});

    try {
      let result;
      
      if (mode === 'login') {
        result = await login(formData.username, formData.password);
      } else {
        // For registration, remove confirmPassword before sending
        const { confirmPassword, ...registerData } = formData;
        result = await register(registerData);
      }

      if (!result.success) {
        setErrors({ submit: result.error });
      }
    } catch (error) {
      setErrors({ submit: 'An unexpected error occurred. Please try again.' });
      console.error('Auth error:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const getSubmitButtonText = () => {
    if (isLoading) {
      return mode === 'login' ? 'Logging in...' : 'Creating account...';
    }
    return mode === 'login' ? 'Login' : 'Create Account';
  };

  const getSwitchModeText = () => {
    return mode === 'login' 
      ? "Don't have an account? Register here" 
      : "Already have an account? Login here";
  };

  return (
    <div className="auth-container">
      <h2>{mode === 'login' ? 'Login' : 'Register'}</h2>
      
      {errors.submit && (
        <div className="auth-error-message">
          {errors.submit}
        </div>
      )}

      <form onSubmit={handleSubmit} className="auth-form">
        <div className="auth-form-group">
          <label htmlFor="username">Username:</label>
          <input
            id="username"
            type="text"
            name="username"
            value={formData.username}
            onChange={handleInputChange}
            disabled={isLoading}
            placeholder="Enter your username"
            className={errors.username ? 'error' : ''}
          />
          {errors.username && (
            <span className="auth-field-error">{errors.username}</span>
          )}
        </div>

        {mode === 'register' && (
          <div className="auth-form-group">
            <label htmlFor="email">Email:</label>
            <input
              id="email"
              type="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              disabled={isLoading}
              placeholder="Enter your email"
              className={errors.email ? 'error' : ''}
            />
            {errors.email && (
              <span className="auth-field-error">{errors.email}</span>
            )}
          </div>
        )}

        {mode === 'register' && (
          <div className="auth-form-group">
            <label htmlFor="mobile">Mobile Number (optional):</label>
            <input
              id="mobile"
              type="tel"
              name="mobile"
              value={formData.mobile}
              onChange={handleInputChange}
              disabled={isLoading}
              placeholder="Enter your mobile number"
              className={errors.mobile ? 'error' : ''}
            />
            {errors.mobile && (
              <span className="auth-field-error">{errors.mobile}</span>
            )}
          </div>
        )}

        <div className="auth-form-group">
          <label htmlFor="password">Password:</label>
          <input
            id="password"
            type="password"
            name="password"
            value={formData.password}
            onChange={handleInputChange}
            disabled={isLoading}
            placeholder="Enter your password"
            className={errors.password ? 'error' : ''}
          />
          {errors.password && (
            <span className="auth-field-error">{errors.password}</span>
          )}
        </div>

        {mode === 'register' && (
          <div className="auth-form-group">
            <label htmlFor="confirmPassword">Confirm Password:</label>
            <input
              id="confirmPassword"
              type="password"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleInputChange}
              disabled={isLoading}
              placeholder="Confirm your password"
              className={errors.confirmPassword ? 'error' : ''}
            />
            {errors.confirmPassword && (
              <span className="auth-field-error">{errors.confirmPassword}</span>
            )}
          </div>
        )}

        <button
          type="submit"
          className="auth-button"
          disabled={isLoading}
        >
          {isLoading ? (
            <Loader size="small" message="" />
          ) : (
            getSubmitButtonText()
          )}
        </button>
      </form>

      <button
        type="button"
        className="auth-link"
        onClick={onSwitchMode}
        disabled={isLoading}
      >
        {getSwitchModeText()}
      </button>

      {mode === 'login' && (
        <div className="auth-features">
          <h4>Demo Features:</h4>
          <ul>
            <li>Secure ECIES encryption</li>
            <li>Real-time messaging</li>
            <li>Multi-format steganography</li>
            <li>Auto-delete functionality</li>
          </ul>
        </div>
      )}
    </div>
  );
};

export default AuthForm;