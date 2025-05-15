from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4
from api.handlers.secutils import PassHash, AesEncDBField, AesDecDBField
import os

from .base import BaseHandler

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

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
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        
        #retrieve  salt and email. 
        user = yield self.db.users.find_one({
          'email': email
        }, {
          'email':1, 'password': 1, 'salt':1
        }
        )

       
        if user is None:
            self.send_error(403, message='The email address and invalid!')
            return

       
        # Retrieve Pepper
        with open('StoredPepper', 'rb') as binary_file:
                pepper = binary_file.read()

        # Retrieve keyhash
        salt = user['salt']
                     
        # hash passphrase
        hashed_pass = PassHash(password, salt, pepper)
       

         #Task 3: Verify Keyed Hash 
        if user['password'] != hashed_pass:
            self.send_error(403, message='The password are invalid!')
            return

        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
