import React, { useState } from 'react';
import Loader from '../Common/Loader';
import { stegoAPI } from '../../services/api';

const StegoOperations = ({ fileType, onOperationComplete }) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleFileSelect = (file) => {
    setSelectedFile(file);
    setResult(null);
  };

  const handleEncode = async () => {
    if (!selectedFile || !message) return;

    setLoading(true);
    try {
      const stegoFile = await stegoAPI.encode(selectedFile, message, fileType);
      const downloadUrl = URL.createObjectURL(stegoFile);
      
      setResult({
        type: 'encode',
        downloadUrl,
        fileName: `stego_${selectedFile.name}`
      });
      
      onOperationComplete?.();
    } catch (error) {
      console.error('Encoding error:', error);
      alert('Encoding failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDecode = async () => {
    if (!selectedFile) return;

    setLoading(true);
    try {
      const decodedMessage = await stegoAPI.decode(selectedFile, fileType);
      setResult({
        type: 'decode',
        message: decodedMessage
      });
    } catch (error) {
      console.error('Decoding error:', error);
      alert('Decoding failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="stego-operations">
      <div className="file-selection">
        <input
          type="file"
          accept={fileType === 'image' ? 'image/*' : fileType === 'audio' ? 'audio/*' : 'video/*'}
          onChange={(e) => handleFileSelect(e.target.files[0])}
        />
        {selectedFile && (
          <p>Selected: {selectedFile.name}</p>
        )}
      </div>

      <div className="message-input">
        <textarea
          placeholder="Enter secret message to hide"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          rows={3}
        />
        <p>Character count: {message.length}</p>
      </div>

      <div className="operation-buttons">
        <button 
          onClick={handleEncode} 
          disabled={!selectedFile || !message || loading}
        >
          Encode
        </button>
        <button 
          onClick={handleDecode} 
          disabled={!selectedFile || loading}
        >
          Decode
        </button>
      </div>

      {loading && <Loader />}

      {result && (
        <div className="result">
          {result.type === 'encode' && (
            <div>
              <p>Encoding successful!</p>
              <a 
                href={result.downloadUrl} 
                download={result.fileName}
                className="download-btn"
              >
                Download Stego File
              </a>
            </div>
          )}
          {result.type === 'decode' && (
            <div>
              <p>Decoded message:</p>
              <div className="decoded-message">
                {result.message}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default StegoOperations;