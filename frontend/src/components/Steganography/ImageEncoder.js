import React, { useState } from 'react';
import StegoOperations from './StegoOperations';

const ImageEncoder = () => {
  const [selectedFormat, setSelectedFormat] = useState('jpg');

  return (
    <div className="image-encoder">
      <h3>Image Steganography</h3>
      
      <div className="format-selector">
        <label>Select Image Format:</label>
        <select
          value={selectedFormat}
          onChange={(e) => setSelectedFormat(e.target.value)}
        >
          <option value="jpg">JPG</option>
        </select>
      </div>

      <StegoOperations
        fileType="image"
        acceptedFormats={selectedFormat === 'jpg' ? 'image/jpeg' : 'image/png'}
        onOperationComplete={() => console.log('Operation completed')}
      />
    </div>
  );
};

export default ImageEncoder;