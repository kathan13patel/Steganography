import React from 'react';

const HowToUse = () => {
  return (
    <div className="how-to-use">
      <h2>How to Use Steganography Chat</h2>
      
      <div className="instruction-section">
        <h3>1. Registration & Login</h3>
        <p>Create an account with your username, email, and password. Then login to access the chat features.</p>
      </div>

      <div className="instruction-section">
        <h3>2. Encoding Messages</h3>
        <p>To hide a message in a file:</p>
        <ul>
          <li>Select a file (Image JPG/PNG, Audio WAV, or Video MP4)</li>
          <li>Enter your secret message</li>
          <li>Click "Encode" to create a stego file</li>
          <li>Download the encoded file</li>
        </ul>
      </div>

      <div className="instruction-section">
        <h3>3. Decoding Messages</h3>
        <p>To extract a hidden message:</p>
        <ul>
          <li>Upload a stego file</li>
          <li>Click "Decode" to extract the hidden message</li>
          <li>View the decoded message in the results area</li>
        </ul>
      </div>

      <div className="instruction-section">
        <h3>4. Chat Features</h3>
        <p>Send encoded files to other users:</p>
        <ul>
          <li>Select a user from the list</li>
          <li>Send text messages or encoded files</li>
          <li>Files auto-delete after specified time</li>
          <li>Download received files</li>
        </ul>
      </div>

      <div className="instruction-section">
        <h3>5. Security Features</h3>
        <p>Your messages are protected with:</p>
        <ul>
          <li>ECIES encryption for text messages</li>
          <li>DWT + DCT steganography algorithms</li>
          <li>Auto-deletion of sensitive files</li>
          <li>No password required for stego files</li>
        </ul>
      </div>
    </div>
  );
};

export default HowToUse;