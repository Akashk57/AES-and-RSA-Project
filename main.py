from aes_encryption import aes_encrypt, aes_decrypt
from rsa_encryption import generate_rsa_keys, rsa_encrypt, rsa_decrypt
from hashing import sha256_hash
from performance_measurement import measure_time
from Crypto.Random import get_random_bytes



if __name__ == "__main__":
    # Input text from user
    plain_text = input("Enter the text you want to encrypt: ")

    # AES Example
    key = get_random_bytes(16)
    
    aes_enc_time, aes_dec_time = measure_time(aes_encrypt, aes_decrypt, plain_text, key)
    aes_encrypted_data = aes_encrypt(plain_text, key)
    aes_decrypted_text = aes_decrypt(aes_encrypted_data, key)
    
    print(f"\nAES Encryption Time: {aes_enc_time:.6f}, Decryption Time: {aes_dec_time:.6f}")
    print(f"AES Encrypted Data: {aes_encrypted_data}")
    print(f"AES Decrypted Text: {aes_decrypted_text}")

    # RSA Example
    private_key, public_key = generate_rsa_keys()
    rsa_enc_time, rsa_dec_time = measure_time(rsa_encrypt, rsa_decrypt, plain_text, public_key, private_key)
    rsa_encrypted_data = rsa_encrypt(plain_text, public_key)
    rsa_decrypted_text = rsa_decrypt(rsa_encrypted_data, private_key)
    
    print(f"\nRSA Encryption Time: {rsa_enc_time:.6f}, Decryption Time: {rsa_dec_time:.6f}")
    print(f"RSA Encrypted Data: {rsa_encrypted_data}")
    print(f"RSA Decrypted Text: {rsa_decrypted_text}")

    # SHA-256 Example (Note: Hashing is a one-way function and cannot be decrypted)
    hash_value = sha256_hash(plain_text)
    print(f"\nSHA-256 Hash: {hash_value}")

   


