import os

key = os.urandom(16) # crypographic random value on a per Application values
with open('StoredKey', 'wb') as binary_file:
    binary_file.write(key)
