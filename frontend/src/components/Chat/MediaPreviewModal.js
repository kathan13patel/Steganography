import React from 'react';
import './css/MediaPreviewModal.css';

const MediaPreviewModal = ({ media, isOpen, onClose }) => {
    if (!isOpen || !media) return null;

    const renderMediaContent = () => {
        switch (media.type) {
            case 'image':
                return (
                    <img 
                        src={media.url || media.stego_url} 
                        alt={media.name || 'Image preview'}
                        className="media-preview-content-image"
                        onError={(e) => {
                            e.target.src = 'https://via.placeholder.com/500x300?text=Image+Not+Found';
                        }}
                    />
                );
            
            case 'audio':
                return (
                    <div className="audio-player-container">
                        <audio 
                            controls 
                            autoPlay 
                            className="media-preview-content"
                        >
                            <source src={media.url || media.stego_url} type="audio/mpeg" />
                            <source src={media.url || media.stego_url} type="audio/wav" />
                            Your browser does not support the audio element.
                        </audio>
                    </div>
                );
            
            default:
                return (
                    <div className="unknown-media">
                        <i className="fas fa-file"></i>
                        <p>Unsupported media type</p>
                    </div>
                );
        }
    };

    return (
        <div className="media-modal-overlay" onClick={onClose}>
            <div className="media-modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="media-modal-header">
                    <div className="header-title-container">
                        <h3 className="truncate-title">{media.name || 'Media Preview'}</h3>
                    </div>
                    <button className="modal-close-btn" onClick={onClose}>
                        <i className="fas fa-times"></i>
                    </button>
                </div>
                
                <div className="media-preview-container">
                    {renderMediaContent()}
                </div>
                
                {/* <div className="media-modal-footer">
                    <button 
                        className="download-btn-2"
                        onClick={() => {
                            const link = document.createElement('a');
                            link.href = media.url || media.stego_url;
                            link.download = media.name || 'download';
                            link.target = '_blank';
                            document.body.appendChild(link);
                            link.click();
                            document.body.removeChild(link);
                        }}
                    >
                        <i className="fas fa-download"></i>
                        Download
                    </button>
                </div> */}
                {/* Add this near your MediaPreviewModal */}
            </div>
        </div>
    );
};

export default MediaPreviewModal;