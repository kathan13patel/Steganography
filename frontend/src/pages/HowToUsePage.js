
import React, { useEffect } from 'react';
import { useAuth } from '../services/auth';
import { useNavigate } from 'react-router-dom';
import '../pages/css/HowToUsePage.css';

const HowToUsePage = () => {
    const { isAuthenticated, loading } = useAuth();
    const navigate = useNavigate();

    useEffect(() => {
        if (!loading && !isAuthenticated) {
            navigate('/login');
        }
    }, [loading, isAuthenticated, navigate]);

    if (loading) return <div>Loading...</div>;

    return (
        <div className="howto-container">
            <h1 className="howto-title">How to Use Steganography Chat</h1>
            <ol className="howto-steps">
                <li>
                    <strong>Register:</strong> Create your account using a valid email and password.
                </li>
                <li>
                    <strong>Login:</strong> Enter your credentials to access the chat platform.
                </li>
                <li>
                    <strong>Update Profile:</strong> Edit your profile and upload a profile image if desired.
                </li>
                <li>
                    <strong>Search Users:</strong> Use the search bar to find other users and start a chat.
                </li>
                <li>
                    <strong>Send Messages:</strong> Type and send text messages securely.
                </li>
                <li>
                    <strong>Send Media:</strong> Upload images, audio, or video files. The system will encode your message using steganography before sending.
                </li>
                <li>
                    <strong>Receive Media:</strong> Download and decode steganographic media sent by other users.
                </li>
                <li>
                    <strong>Change Password:</strong> Update your password anytime for security.
                </li>
                <li>
                    <strong>Logout:</strong> Log out securely when finished.
                </li>
            </ol>
            <div className="howto-note">
                <strong>Note:</strong> All media files are processed using steganography and encryption for privacy and security.
            </div>
        </div>
    );
}

export default HowToUsePage;