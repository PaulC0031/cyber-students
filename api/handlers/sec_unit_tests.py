from secutils import PassHash, AesEncDBField, AesDecDBField
import os

with open('StoredPepper', 'rb') as binary_file:
    pepper = binary_file.read()

salt = os.urandom(16) # random value on a per user values
pass_p = 'Ago0dp#a##s##pp@22@'
print(pass_p)

hashed_pass = PassHash(pass_p, salt,pepper)
print("Hashed passphrase: " + hashed_pass.hex())


plaintext = "Test Student info text" # 16 * 8 = 128bits, 1 block
print(plaintext)



#key is cryptographically random
#key = os.urandom(16)
with open('StoredKey', 'rb') as binary_file:
    key = binary_file.read() 

#IV is cryptographically random
iv= os.urandom(16)

plaintext_enc = AesEncDBField(key, plaintext,iv)
print("Ciphertext: " + plaintext_enc)

ciphertext_dec = AesDecDBField(key, plaintext_enc, iv)
print("Original Plaintext: " + ciphertext_dec)


