from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os

# Hash passwords using iterated to produce a keyed hash
def PassHash(pass_p, salt, pepper):
    kdf = Scrypt(salt=salt+pepper, length=32, n=2**16, r=8, p=1) #The Salt(rand per user) and Pepper(rand per app)

    passphrase = pass_p
    passphrase_bytes = bytes(passphrase, "utf-8")
    hashed_passphrase = kdf.derive(passphrase_bytes)
    return hashed_passphrase


# Used to encrypt Document Fields
def AesEncDBField(key, plaintext, iv):

    key_bytes =  key
    iv_bytes = iv
    
    #setup padder 
    padder=padding.PKCS7(algorithms.AES.block_size).padder()
    unpadder=padding.PKCS7(algorithms.AES.block_size).unpadder()


    aes_cipher = Cipher(algorithms.AES(key_bytes),
                        modes.CBC(iv_bytes), # ECB mode insucure never use, using CBC chaining with a cryptographic randomisation vector
                        backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()
    
    plaintext_bytes = bytes(plaintext, "utf-8")
   
    #pad bytes
    padded_bytes = padder.update(plaintext_bytes) + padder.finalize()
    ciphertext_bytes = aes_encryptor.update(padded_bytes) + aes_encryptor.finalize()
    ciphertext = ciphertext_bytes.hex()
    return ciphertext

# Used to decrypt Document Fields    
def AesDecDBField(key, Ciphertext, iv):    
    
    key_bytes = key
    iv_bytes = iv
     
    #setup un padder
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    aes_cipher = Cipher(algorithms.AES(key_bytes),
                        modes.CBC(iv_bytes), 
                        backend=default_backend())

    aes_decryptor = aes_cipher.decryptor()

    hexciphertext = Ciphertext
    hexciphertext_b = bytes.fromhex(hexciphertext)
    padded_bytes_2 = aes_decryptor.update(hexciphertext_b) + aes_decryptor.finalize()
    plaintext_bytes_2 = unpadder.update(padded_bytes_2) + unpadder.finalize()
    plaintext_2 = str(plaintext_bytes_2, "utf-8")
    return plaintext_2
    

