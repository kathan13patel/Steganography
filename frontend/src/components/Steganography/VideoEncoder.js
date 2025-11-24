import React from 'react';
import StegoOperations from './StegoOperations';

const VideoEncoder = () => {
  return (
    <div className="video-encoder">
      <h3>Video Steganography (MP4)</h3>
      <p>Supports MP4 video files only</p>
      
      <StegoOperations
        fileType="video"
        acceptedFormats="video/mp4"
        onOperationComplete={() => console.log('Operation completed')}
      />
    </div>
  );
};

export default VideoEncoder;