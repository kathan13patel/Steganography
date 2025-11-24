import { useCallback } from 'react';

const useDynamicCharCapacity = () => {
    const calculateImageCapacity = useCallback(async (file) => {
        return new Promise((resolve) => {
            const img = new Image();
            img.onload = () => {
                // EXACTLY MATCHING BACKEND: (pixels.size * 3) // 8
                const pixelCount = img.width * img.height;
                const capacity = Math.floor((pixelCount * 3) / 8);
                URL.revokeObjectURL(img.src);
                resolve(capacity);
            };
            img.onerror = () => {
                // Fallback if image loading fails
                resolve(1000);
            };
            img.src = URL.createObjectURL(file);
        });
    }, []);

    const calculateAudioCapacity = useCallback(async (file) => {
        // For MP3 files: file_size // 8 (exactly matching backend)
        if (file.name.toLowerCase().endsWith('.mp3')) {
            return Math.floor(file.size / 8);
        }
        
        // For WAV files - try to read header and calculate like backend
        try {
            const arrayBuffer = await file.arrayBuffer();
            const header = new Uint8Array(arrayBuffer.slice(0, 12));
            
            // Check for WAV RIFF header (like backend)
            const riffHeader = String.fromCharCode.apply(null, header.slice(0, 4));
            if (riffHeader !== 'RIFF') {
                throw new Error("Invalid WAV file: missing RIFF header");
            }
            
            // Read WAV file structure
            const view = new DataView(arrayBuffer);
            
            // Find format chunk
            let offset = 12;
            while (offset + 8 < arrayBuffer.byteLength) {
                const chunkId = String.fromCharCode.apply(null, 
                    new Uint8Array(arrayBuffer.slice(offset, offset + 4)));
                const chunkSize = view.getUint32(offset + 4, true);
                
                if (chunkId === 'fmt ') {
                    // Read format information
                    const audioFormat = view.getUint16(offset + 8, true);
                    const numChannels = view.getUint16(offset + 10, true);
                    const sampleRate = view.getUint32(offset + 12, true);
                    const byteRate = view.getUint32(offset + 16, true);
                    const blockAlign = view.getUint16(offset + 20, true);
                    const bitsPerSample = view.getUint16(offset + 22, true);
                    
                    // Find data chunk
                    let dataOffset = offset + 8 + chunkSize;
                    while (dataOffset + 8 < arrayBuffer.byteLength) {
                        const dataChunkId = String.fromCharCode.apply(null, 
                            new Uint8Array(arrayBuffer.slice(dataOffset, dataOffset + 4)));
                        const dataChunkSize = view.getUint32(dataOffset + 4, true);
                        
                        if (dataChunkId === 'data') {
                            // EXACTLY MATCHING BACKEND: (frames * sample_width * 8) // 8
                            const sampleWidth = bitsPerSample / 8;
                            const totalFrames = dataChunkSize / (numChannels * sampleWidth);
                            const capacity = Math.floor((totalFrames * sampleWidth * 8) / 8);
                            return capacity;
                        }
                        
                        dataOffset += 8 + dataChunkSize;
                    }
                    break;
                }
                
                offset += 8 + chunkSize;
            }
            
            // Fallback if WAV parsing fails
            return Math.floor(file.size / 10);
            
        } catch (error) {
            console.warn('WAV parsing failed, using fallback:', error);
            return Math.floor(file.size / 10);
        }
    }, []);

    const calculateMaxCharCapacity = useCallback(async (file, type) => {
        if (!file) return 1000; // Default for text mode
        
        try {
            let capacity = 0;
            
            switch(type) {
                case 'image':
                    capacity = await calculateImageCapacity(file);
                    break;
                case 'audio':
                    capacity = await calculateAudioCapacity(file);
                    break;
                default:
                    capacity = 1000;
            }
            
            console.log(`Calculated capacity for ${file.name} (${type}):`, capacity);
            
            // Return the exact capacity without artificial limits
            // The backend doesn't impose artificial limits, so neither should we
            return Math.max(capacity, 100); // Minimum 100 characters
            
        } catch (error) {
            console.error('Error calculating capacity:', error);
            
            // Fallback calculations that match backend logic
            switch(type) {
                case 'image':
                    return Math.max(Math.floor(file.size / 4), 100);
                case 'audio':
                    return Math.max(Math.floor(file.size / 10), 100);
                default:
                    return 1000;
            }
        }
    }, [calculateImageCapacity, calculateAudioCapacity]);

    return calculateMaxCharCapacity;
};

export default useDynamicCharCapacity;