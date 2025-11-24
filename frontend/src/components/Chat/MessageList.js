import React from 'react';

const MessageList = ({ messages, currentUser }) => {
  return (
    <div className="message-list">
      {messages.map((message, index) => (
        <div
          key={index}
          className={`message ${message.sender_id === currentUser?.id ? 'own-message' : 'other-message'}`}
        >
          <div className="message-content">
            <p>{message.message}</p>
            {message.file_name && (
              <div className="file-attachment">
                <span>📎 {message.file_name}</span>
              </div>
            )}
            <span className="message-time">
              {new Date(message.timestamp).toLocaleTimeString()}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
};

export default MessageList;