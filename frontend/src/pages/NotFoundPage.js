import React from 'react';
import { useNavigate } from 'react-router-dom';
import './css/NotFoundPage.css';

const NotFoundPage = () => {
  const navigate = useNavigate();

  return (
    <div className="not-found-container">
      {/* Doodle Background Elements */}
      <div className="doodle-orb"></div>
      <div className="doodle-orb"></div>
      <div className="doodle-orb"></div>
      
      <div className="not-found-content">
        <div className="error-doodle">{'>_<'}</div>
        <div className="error-code">404</div>
        <h1 className="error-title">Page Not Found</h1>
        <p className="error-message"> The requested page could not be located. It may have been moved, deleted, or the URL was entered incorrectly.</p>
        <div className="error-suggestions">
        <p>Quick solutions:</p>
        <ul>
            <li>Double-check the URL address</li>
            <li>Use the navigation menu</li>
            <li>Return to safety below</li>
        </ul>
        </div>
        <button className="home-button" onClick={() => navigate('/dashboard')}>Back To Home</button>
      </div>
    </div>
  );
};

export default NotFoundPage;