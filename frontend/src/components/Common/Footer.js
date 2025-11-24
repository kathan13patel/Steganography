import React from 'react';
import { Link } from 'react-router-dom';
import './css/Footer.css';

const Footer = () => {
  return (
    <footer className="app-footer">
      <div className="footer-container">
        <div className="footer-content">
          <div className="footer-section">
            <h3><Link to="/dashboard">StegoChat</Link></h3>
            <p>Secure messaging through steganography. Hide your messages in plain sight within multimedia files.</p>
            {/* \ */}
          </div>
          
          <div className="footer-section">
            <h4>Quick Links</h4>
            <ul>
              <li><Link to="/how-to-use">How to Use</Link></li>
              <li><Link to="/profile">My Profile</Link></li>
              <li><Link to="/faq">FAQ</Link></li>
            </ul>
          </div>
          
          <div className="footer-section">
            <h4>Features</h4>
            <ul>
              <li>Image Steganography</li>
              <li>Audio Steganography</li>
              {/* <li>Video Steganography</li> */}
              <li>Secure Encryption</li>
              {/* <li>Auto-expiring Files</li> */}
            </ul>
          </div>
          
          {/* <div className="footer-section">
            <h4>Support</h4>
            <ul>
              <li><a href="#">Help Center</a></li>
              <li><a href="#">FAQ</a></li>
              <li><a href="#">Contact Us</a></li>
              <li><a href="#">Privacy Policy</a></li>
              <li><a href="#">Terms of Service</a></li>
            </ul>
          </div> */}
        </div>
        
        <div className="footer-bottom">
          <p>&copy; {new Date().getFullYear()} StegoChat. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;