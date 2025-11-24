import numpy as np
import wave
import pywt
from scipy.fftpack import dct, idct
import struct

class AudioSteganography:
    def __init__(self):
        self.wavelet = 'db4'
    
    def encode_wav(self, audio_path, secret_message):
        # Read WAV file
        with wave.open(audio_path, 'rb') as audio_file:
            params = audio_file.getparams()
            frames = audio_file.readframes(params.nframes)
        
        # Convert to numpy array
        audio_data = np.frombuffer(frames, dtype=np.int16)
        
        # Apply DWT
        coeffs = pywt.wavedec(audio_data, self.wavelet, level=2)
        cA = coeffs[0]
        
        # Apply DCT
        dct_coeffs = dct(cA, norm='ortho')
        
        # Embed message
        encoded_coeffs = self._embed_message(dct_coeffs, secret_message)
        
        # Inverse DCT
        idct_coeffs = idct(encoded_coeffs, norm='ortho')
        
        # Reconstruct coefficients
        coeffs[0] = idct_coeffs
        
        # Inverse DWT
        stego_audio = pywt.waverec(coeffs, self.wavelet)
        stego_audio = stego_audio.astype(np.int16)
        
        # Save as WAV
        return stego_audio, params
    
    def decode_wav(self, stego_audio_path):
        # Read stego WAV file
        with wave.open(stego_audio_path, 'rb') as audio_file:
            frames = audio_file.readframes(audio_file.getparams().nframes)
        
        audio_data = np.frombuffer(frames, dtype=np.int16)
        
        # Apply DWT
        coeffs = pywt.wavedec(audio_data, self.wavelet, level=2)
        cA = coeffs[0]
        
        # Apply DCT
        dct_coeffs = dct(cA, norm='ortho')
        
        # Extract message
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
        
        return flat_coeffs
    
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