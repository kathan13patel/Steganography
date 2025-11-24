import React, { useState } from 'react';
import UserSearch from '../components/Common/UserSearch';
import Chat from '../components/Chat/ChatWindow';
import './css/Dashboard.css';
// import './css/DashboardStatic.css';

const Dashboard = () => {
  const [isSearchOpen, setSearchOpen] = useState(false);
  const [activeChats, setActiveChats] = useState([]);

  const handleStartChat = (user) => {
    console.log('Starting chat with:', user);
    
    // Check if chat already exists
    const existingChat = activeChats.find(chat => chat.user.id === user.id);
    
    if (!existingChat) {
      // Create new chat
      setActiveChats([...activeChats, { user, isOpen: true }]);
    }
    
    setSearchOpen(false);
  };

  const closeChat = (userId) => {
    setActiveChats(activeChats.filter(chat => chat.user.id !== userId));
  };

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <p>Welcome to the Steganography Chat Application</p>
      </div>

           {/* Search Button */}
      <button
        onClick={() => setSearchOpen(true)}
      >
        Find Users
      </button>

      {/* Functionality Cards Row */}
      <div className="dashboard-row">
        <div className="dashboard-card">
          <div className="dashboard-card-title">Secure Messaging</div>
          <div className="dashboard-card-desc">
            Send and receive real-time text messages with encryption for privacy and security.
          </div>
        </div>
        <div className="dashboard-card">
          <div className="dashboard-card-title">Steganography Media</div>
          <div className="dashboard-card-desc">
            Share images, audio, and video files encoded with hidden messages using steganography.
          </div>
        </div>
        <div className="dashboard-card">
          <div className="dashboard-card-title">Profile & Search</div>
          <div className="dashboard-card-desc">
            Manage your profile, change password, and search for users to start secure conversations.
          </div>
        </div>
      </div>

      {/* Display Active Chats */}
      <div className="chats-container">
        {activeChats.map(chat => (
          <Chat 
            key={chat.user.id} 
            user={chat.user} 
            onClose={() => closeChat(chat.user.id)}
          />
        ))}
      </div>

      {/* User Search Modal */}
      <UserSearch 
        isOpen={isSearchOpen} 
        onClose={() => setSearchOpen(false)}
        onStartChat={handleStartChat}
      />
    </div>
  );
};

export default Dashboard;