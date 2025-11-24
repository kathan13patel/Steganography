import React from 'react';
import StegoOperations from './StegoOperations';

const AudioEncoder = () => {
  return (
    <div className="audio-encoder">
      <h3>Audio Steganography (WAV)</h3>
      <p>Supports WAV audio files only</p>
      
      <StegoOperations
        fileType="audio"
        acceptedFormats="audio/wav"
        onOperationComplete={() => console.log('Operation completed')}
      />
    </div>
  );
};

export default AudioEncoder;