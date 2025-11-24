import React, { useState } from 'react';
import { checkServerConnection } from '../services/api';

const TestConnection = () => {
  const [status, setStatus] = useState('Not tested');
  const [loading, setLoading] = useState(false);

  const testConnection = async () => {
    setLoading(true);
    setStatus('Testing...');
    
    try {
      const result = await checkServerConnection();
      setStatus(result ? 'Connected successfully!' : 'Connection failed');
    } catch (error) {
      setStatus(`Error: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '20px', border: '1px solid #ccc', margin: '20px' }}>
      <h3>Connection Test</h3>
      <p>Status: {status}</p>
      <button onClick={testConnection} disabled={loading}>
        {loading ? 'Testing...' : 'Test Connection'}
      </button>
    </div>
  );
};

export default TestConnection;
