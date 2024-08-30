from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_encrypt(plain_text, key):
    data = plain_text.encode('utf-8')
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return iv + ct_bytes

def aes_decrypt(enc_data, key):
    iv = enc_data[:16]
    ct = enc_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(ct), AES.block_size)
    return plain_text.decode('utf-8')
