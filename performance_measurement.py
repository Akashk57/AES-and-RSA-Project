import time

def measure_time(encryption_func, decryption_func, data, pub_key, priv_key=None):
    start_time = time.time()
    encrypted_data = encryption_func(data, pub_key)
    encryption_time = time.time() - start_time
    
    start_time = time.time()
    # Use pub_key if priv_key is None (for symmetric encryption like AES)
    decryption_func(encrypted_data, priv_key if priv_key else pub_key)
    decryption_time = time.time() - start_time
    
    return encryption_time, decryption_time

