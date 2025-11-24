import React, { useState } from 'react';

const MessageInput = ({ onSendMessage, selectedUser }) => {
  const [message, setMessage] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (message.trim() && selectedUser) {
      onSendMessage(message.trim());
      setMessage('');
    }
  };

  return (
    <form onSubmit={handleSubmit} className="message-input-form">
      <div className="input-container">
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Type your message..."
          disabled={!selectedUser}
        />
        <button type="submit" disabled={!message.trim() || !selectedUser}>
          Send
        </button>
      </div>
      <div className="character-count">
        {message.length}/1000 characters
      </div>
    </form>
  );
};

export default MessageInput;