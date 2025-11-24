import cv2
import numpy as np
import pywt
from scipy.fftpack import dct, idct

class VideoSteganography:
    def __init__(self):
        self.wavelet = 'haar'
    
    def encode_mp4(self, video_path, secret_message):
        cap = cv2.VideoCapture(video_path)
        frames = []
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            # Convert to grayscale for simplicity
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            frames.append(gray_frame)
        
        cap.release()
        
        # Use first frame for embedding
        if frames:
            stego_frame = self._encode_frame(frames[0], secret_message)
            frames[0] = stego_frame
        
        # Reconstruct video (simplified)
        return frames
    
    def decode_mp4(self, stego_video_path):
        cap = cv2.VideoCapture(stego_video_path)
        frames = []
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            frames.append(gray_frame)
        
        cap.release()
        
        if frames:
            return self._decode_frame(frames[0])
        return ""
    
    def _encode_frame(self, frame, message):
        coeffs = pywt.wavedec2(frame, self.wavelet, level=2)
        cA, (cH, cV, cD) = coeffs[0], coeffs[1:]
        
        dct_coeffs = dct(dct(cA.T, norm='ortho').T, norm='ortho')
        encoded_coeffs = self._embed_message(dct_coeffs, message)
        idct_coeffs = idct(idct(encoded_coeffs.T, norm='ortho').T, norm='ortho')
        
        new_coeffs = (idct_coeffs, (cH, cV, cD))
        stego_frame = pywt.waverec2(new_coeffs, self.wavelet)
        
        return stego_frame.astype(np.uint8)
    
    def _decode_frame(self, frame):
        coeffs = pywt.wavedec2(frame, self.wavelet, level=2)
        cA = coeffs[0]
        dct_coeffs = dct(dct(cA.T, norm='ortho').T, norm='ortho')
        
        return self._extract_message(dct_coeffs)
    
    def _embed_message(self, coefficients, message):
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        binary_message += '00000000'
        
        flat_coeffs = coefficients.flatten()
        message_index = 0
        
        for i in range(len(flat_coeffs)):
            if message_index < len(binary_message):
                flat_coeffs[i] = int(flat_coeffs[i]) & ~1 | int(binary_message[message_index])
                message_index += 1
            else:
                break
        
        return flat_coeffs.reshape(coefficients.shape)
    
    def _extract_message(self, coefficients):
        flat_coeffs = coefficients.flatten()
        binary_message = ''
        
        for coeff in flat_coeffs:
            binary_message += str(int(coeff) & 1)
            if len(binary_message) % 8 == 0:
                if binary_message[-8:] == '00000000':
                    break
        
        message = ''
        for i in range(0, len(binary_message)-8, 8):
            byte = binary_message[i:i+8]
            message += chr(int(byte, 2))
        
        return message