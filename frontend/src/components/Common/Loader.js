import React from 'react';
import './css/Loader.css';

const Loader = ({ size = 'medium', message = 'Processing...' }) => {
  return (
    <div className="loader-container">
      <div className={`loader ${size}`}>
        <div className="loader-spinner"></div>
      </div>
      {message && <p className="loader-message">{message}</p>}
    </div>
  );
};

export default Loader;