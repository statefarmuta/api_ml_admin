import datetime
from flask import session
from app.common.database import Database
from flask_login import UserMixin
import jwt
import datetime
from app import app, bc

class BlacklistToken():
    """
    Token Model for storing JWT tokens
    """
    
    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = Database.find_one(collection='blacklist_tokens', query={'token': auth_token})
        if res:
            return True
        else:
            return False
    

    def json(self):
        return {
            "token": self.token,
            "blacklisted_on": self.blacklisted_on
        }

    
    def save_to_mongo(self):
        Database.insert(collection='blacklist_tokens', data=self.json())