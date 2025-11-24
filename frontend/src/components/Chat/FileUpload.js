import React, { useState } from 'react';

const FileUpload = ({ onFileSelect }) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileType, setFileType] = useState('image');

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleUpload = () => {
    if (selectedFile) {
      onFileSelect(selectedFile, fileType);
      setSelectedFile(null);
      // Reset file input
      document.getElementById('file-input').value = '';
    }
  };

  return (
    <div className="file-upload">
      <h4>Upload File</h4>
      <div className="upload-controls">
        <select
          value={fileType}
          onChange={(e) => setFileType(e.target.value)}
        >
          <option value="image">Image (JPG/PNG)</option>
          <option value="audio">Audio (WAV)</option>
          <option value="video">Video (MP4)</option>
        </select>
        
        <input
          id="file-input"
          type="file"
          accept={fileType === 'image' ? 'image/jpeg,image/png' : fileType === 'audio' ? 'audio/wav' : 'video/mp4'}
          onChange={handleFileChange}
        />
        
        <button
          onClick={handleUpload}
          disabled={!selectedFile}
        >
          Upload File
        </button>
      </div>
      
      {selectedFile && (
        <div className="file-info">
          <p>Selected: {selectedFile.name}</p>
          <p>Size: {(selectedFile.size / 1024).toFixed(2)} KB</p>
        </div>
      )}
    </div>
  );
};

export default FileUpload;