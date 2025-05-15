from .base import BaseHandler
from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from api.handlers.secutils import PassHash, AesEncDBField, AesDecDBField
import os


class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            
            # User Details
            display_name = body.get('displayName')
            full_name = body.get('fullName')
            address = body.get('address')
            phone_number = body.get('phoneNumber')
            disabilities = body.get('disabilities')
                     
                       
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        
        
        #Task 1: Password Salted, Peppered and Iterively Hashed. Store the keyed hash, iv and salt in Mongodb. 
        # I'm including password Peppering, as in the Passphrase Storage & Verication lecture notes, salting alone is not enough.
        # Store pepper in a binary file.  
        
        with open('StoredPepper', 'rb') as binary_file:
            pepper = binary_file.read()
        
        salt = os.urandom(16) # cryptographic random value for salt; on a per user basis
                     
        hashed_pass = PassHash(password, salt, pepper)
        
 

        # Task 4: Encrypt and upload Personal Details to MongoDB Document
        ## Task 2: Store key in binary file. key is cryptographically random 

        with open('StoredKey', 'rb') as binary_file:
            key = binary_file.read()

        #IV is cryptographically random
        iv= os.urandom(16)

        display_name_aes = AesEncDBField(key, display_name, iv)
        full_name_aes = AesEncDBField(key, full_name,iv)
        address_aes = AesEncDBField(key, address, iv)
        phone_number_aes = AesEncDBField(key, phone_number, iv)
        disabilities_aes = AesEncDBField(key, disabilities, iv)
        
   
        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_pass, 
            'displayName': display_name_aes, 
            'Full Name': full_name_aes,
            'Address': address_aes,
            'Phone Number': phone_number_aes,
            'Disabilities': disabilities_aes,
            'salt': salt,
            'iv': iv
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name
        self.write_json()
