import hashlib
import re

def validate_key(key, key_size):
    """Validate if key is strong enough for selected key size"""
    try:
        # Minimum length requirements (approximate)
        min_lengths = {
            '128': 8,  # ~8 chars for 128-bit
            '192': 12, # ~12 chars for 192-bit
            '256': 16  # ~16 chars for 256-bit
        }
        
        # Check if key meets minimum complexity
        if len(key) < min_lengths[key_size]:
            return False
            
        # Check for basic complexity (at least some variation)
        if len(set(key)) < 3:
            return False
            
        return True
    except:
        return False

def process_key(key, key_size):
    """Process key to required byte length"""
    # Determine required byte length
    byte_length = int(key_size) // 8
    
    # Convert key to bytes
    key_bytes = key.encode('utf-8')
    
    # If key is too short, extend with SHA-256 hash
    if len(key_bytes) < byte_length:
        hash_obj = hashlib.sha256(key_bytes)
        key_bytes += hash_obj.digest()
    
    # If key is too long, truncate
    key_bytes = key_bytes[:byte_length]
    
    return key_bytes