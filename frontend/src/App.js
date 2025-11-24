import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Header from './components/Common/Header';
import Footer from './components/Common/Footer';
import Login from './components/Auth/Login';
import Register from './components/Auth/Register';
import Dashboard from './pages/Dashboard';
import ProfilePage from './pages/ProfilePage';
import Modal from './components/Common/Modal';
import HowToUsePage from './pages/HowToUsePage';
import FAQ from './pages/FAQ';
import AuthForm from './components/Auth/AuthForm';
import ChatWindow from './components/Chat/ChatWindow';
import Loader from './components/Common/Loader';
import NotFoundPage from './pages/NotFoundPage';
import { AuthProvider, useAuth } from './services/auth';    
import '@fortawesome/fontawesome-free/css/all.min.css';
import './App.css';

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="App">
          <AppContent />
        </div>
      </Router>
    </AuthProvider>
  );
}

function AppContent() {
  const { user, loading } = useAuth();

    // Show loading spinner until auth check completes
    if (loading) {
        return (
        <div className="loading-container">
            <Loader />
            <p>Loading...</p>
        </div>
        );
    }

    const PageLayout = ({ children, requireAuth = true }) => {
        if (requireAuth && !user) {
        return <Navigate to="/login" />;
        }

        return (
        <div className="page-layout">
            <Header />
            <main className="main-content">
            {children}
            </main>
            <Footer />
        </div>
        );
    };

    return (
        <Routes>
        {/* Auth Pages */}
        <Route path="/login" element={user ? <Navigate to="/dashboard" /> : <Login />} />
        <Route path="/register" element={user ? <Navigate to="/dashboard" /> : <Register />} />

        {/* Main Pages */}
        <Route path="/dashboard" element={<PageLayout><Dashboard /></PageLayout>} />
        <Route path="/chat/:userId" element={ user ? <ChatWindow /> : <Navigate to="/login" replace />}/>
        <Route path="/chat/*" element={<Navigate to="/dashboard" replace />} />
        <Route path="/profile" element={<PageLayout><ProfilePage /></PageLayout>} />
        <Route path="/faq" element={<PageLayout requireAuth={false}><FAQ /></PageLayout>} />
        <Route path="/how-to-use" element={<PageLayout requireAuth={false}><HowToUsePage /></PageLayout>} />

        {/* Extra Component Routes (For Testing) */}
        <Route path="/auth-form" element={<PageLayout><AuthForm /></PageLayout>} />
        {/* <Route path="/chat-window" element={<PageLayout><ChatWindow /></PageLayout>} /> */}
        <Route path="/loader" element={<PageLayout><Loader /></PageLayout>} />
        <Route path="/footer" element={<Footer />} />
        <Route path="/header" element={<Header />} />
        <Route path="/modal" element={<Modal />} />
        <Route path="/404" element={<NotFoundPage />} />
        <Route path="*" element={<NotFoundPage />} />    

        {/* Default Redirect */}
        <Route path="/" element={<Navigate to={user ? "/dashboard" : "/login"} />} />
        <Route path="*" element={<Navigate to={user ? "/dashboard" : "/login"} replace />} />
        </Routes>
    );
}

export default App;
