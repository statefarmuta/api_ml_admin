from datetime import datetime
#from app import login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class Session_User():

    def __init__(self, username, hash, uid):
        self.name = username
        self.hash = hash
        self.uid = uid
          