from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_file(input_path, output_path, key, key_size):
    try:
        # Read input file
        with open(input_path, 'rb') as f:
            iv = f.read(AES.block_size)
            ciphertext = f.read()
        
        # Create cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt the data
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        # Write decrypted data
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return True
    except ValueError as e:
        # This occurs when padding is incorrect (wrong key)
        raise Exception("Khóa giải mã không đúng")
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        raise Exception("Lỗi giải mã file")