from tornado.web import authenticated
from api.handlers.secutils import PassHash, AesEncDBField, AesDecDBField

import os


from .auth import AuthHandler

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        
        #key is cryptographically random
        with open('StoredKey', 'rb') as binary_file:
            key = binary_file.read()

        # Retrieve iv and decrypt and Send Personal Details Fields
        iv = self.current_user['iv']
        
        display_name = AesDecDBField(key, self.current_user['display_name'], iv)
        full_name = AesDecDBField(key, self.current_user['full_name'],iv)
        address = AesDecDBField(key, self.current_user['address'], iv)
        phone_number = AesDecDBField(key, self.current_user['phone_number'], iv)
        disabilities = AesDecDBField(key, self.current_user['disabilities'], iv)
        
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = display_name
        self.response['fullName'] = full_name
        self.response['address'] = address
        self.response['phoneNumber'] = phone_number
        self.response['disabilities'] = disabilities
        
        self.write_json()
        
               
        # Added more personal details as per question and automated test should still pass.  
        # run_hacker; can only see cipher text not plain text details when listening from the database 