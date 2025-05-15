import os

pepper = os.urandom(16) # crypographic random value on a per Application values
with open('StoredPepper', 'wb') as binary_file:
    binary_file.write(pepper)

