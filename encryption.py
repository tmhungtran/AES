from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import os

def encrypt_file(input_path, output_path, key, key_size):
    try:
        # Generate random IV
        iv = get_random_bytes(AES.block_size)
        
        # Create cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Read input file
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        # Encrypt the data
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        
        # Write IV + ciphertext to output file
        with open(output_path, 'wb') as f:
            f.write(iv)
            f.write(ciphertext)
        
        return True
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return False