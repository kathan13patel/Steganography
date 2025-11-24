import numpy as np
import cv2
import pywt
from scipy.fftpack import dct, idct

class ImageSteganography:
    def __init__(self):
        self.wavelet = 'haar'
        
    def encode_jpg(self, image_path, secret_message):
        # DWT + DCT for JPG
        img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        
        # Perform DWT
        coeffs = pywt.wavedec2(img, self.wavelet, level=2)
        cA, (cH, cV, cD) = coeffs[0], coeffs[1:]
        
        # Apply DCT to approximation coefficients
        dct_coeffs = dct(dct(cA.T, norm='ortho').T, norm='ortho')
        
        # Embed message in DCT coefficients
        encoded_coeffs = self._embed_message(dct_coeffs, secret_message)
        
        # Inverse DCT
        idct_coeffs = idct(idct(encoded_coeffs.T, norm='ortho').T, norm='ortho')
        
        # Reconstruct coefficients
        new_coeffs = (idct_coeffs, (cH, cV, cD))
        
        # Inverse DWT
        stego_image = pywt.waverec2(new_coeffs, self.wavelet)
        
        return stego_image.astype(np.uint8)
    
    def encode_png(self, image_path, secret_message):
        # Similar to JPG but with lossless handling
        img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
        
        if len(img.shape) == 3:
            # Handle RGB images
            channels = cv2.split(img)
            encoded_channels = []
            
            for channel in channels:
                coeffs = pywt.wavedec2(channel, self.wavelet, level=2)
                cA, (cH, cV, cD) = coeffs[0], coeffs[1:]
                
                dct_coeffs = dct(dct(cA.T, norm='ortho').T, norm='ortho')
                encoded_coeffs = self._embed_message(dct_coeffs, secret_message)
                idct_coeffs = idct(idct(encoded_coeffs.T, norm='ortho').T, norm='ortho')
                
                new_coeffs = (idct_coeffs, (cH, cV, cD))
                encoded_channel = pywt.waverec2(new_coeffs, self.wavelet)
                encoded_channels.append(encoded_channel)
            
            stego_image = cv2.merge(encoded_channels)
        else:
            # Grayscale image
            coeffs = pywt.wavedec2(img, self.wavelet, level=2)
            cA, (cH, cV, cD) = coeffs[0], coeffs[1:]
            
            dct_coeffs = dct(dct(cA.T, norm='ortho').T, norm='ortho')
            encoded_coeffs = self._embed_message(dct_coeffs, secret_message)
            idct_coeffs = idct(idct(encoded_coeffs.T, norm='ortho').T, norm='ortho')
            
            new_coeffs = (idct_coeffs, (cH, cV, cD))
            stego_image = pywt.waverec2(new_coeffs, self.wavelet)
        
        return stego_image.astype(np.uint8)
    
    def decode_jpg(self, stego_image_path):
        img = cv2.imread(stego_image_path, cv2.IMREAD_GRAYSCALE)
        return self._extract_message(img)
    
    def decode_png(self, stego_image_path):
        img = cv2.imread(stego_image_path, cv2.IMREAD_UNCHANGED)
        return self._extract_message(img)
    
    def _embed_message(self, coefficients, message):
        # Convert message to binary
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        binary_message += '00000000'  # Null terminator
        
        flat_coeffs = coefficients.flatten()
        message_index = 0
        
        for i in range(len(flat_coeffs)):
            if message_index < len(binary_message):
                # LSB embedding
                flat_coeffs[i] = int(flat_coeffs[i]) & ~1 | int(binary_message[message_index])
                message_index += 1
            else:
                break
        
        return flat_coeffs.reshape(coefficients.shape)
    
    def _extract_message(self, stego_image):
        coeffs = pywt.wavedec2(stego_image, self.wavelet, level=2)
        cA = coeffs[0]
        dct_coeffs = dct(dct(cA.T, norm='ortho').T, norm='ortho')
        
        flat_coeffs = dct_coeffs.flatten()
        binary_message = ''
        
        for coeff in flat_coeffs:
            binary_message += str(int(coeff) & 1)
            if len(binary_message) % 8 == 0:
                if binary_message[-8:] == '00000000':
                    break
        
        # Convert binary to text
        message = ''
        for i in range(0, len(binary_message)-8, 8):
            byte = binary_message[i:i+8]
            message += chr(int(byte, 2))
        
        return message