import uuid
import datetime
from flask import session
from app.common.database import Database
from flask_login import UserMixin
import jwt
import datetime
from app import app, bc
from app.models.BlacklistToken import BlacklistToken

class User(UserMixin, object):

    # the main variable in user model
    def __init__(self, fname, lname, uname, email, password, profile_pic=None, bio=None, user_id=None, _id=None, is_admin=False):
        self.fname = fname
        self.lname = lname
        self.uname = uname
        self.email = email
        self.password = password
        self.profile_pic = 'default' if profile_pic is None else profile_pic
        self.bio = 'Hey this is ' + 'fname' if bio is None else bio
        self.user_id = int(str(uuid.uuid4().int)[:6]) if user_id is None else user_id
        self.is_admin = is_admin

    # use @classmethod for having returned an user object
    @classmethod
    def get_by_email(cls, email):
        # check the database, users collection for the pair email, password
        data = Database.find_one(collection='users', query={'email': email})
        if data is not None:
            # return the object user
            return cls(**data)

    # use @classmethod for having returned an user object
    @classmethod
    def get_by_username(cls, uname):
        # check the database, users collection for the pair email, password
        data = Database.find_one(collection='users', query={'uname': uname})
        if data is not None:
            # return the object user
            return cls(**data)

    # the same with this one
    @classmethod
    def get_by_id(cls, _id):
        data = Database.find_one(collection='users', query={'user_id': _id})
        if data is not None:
            # return the object user
            return cls(**data)

    # not use self
    @staticmethod
    def login_valid(email, password):
        # User.login_valid('mihai@email.com', '1234')
        # check whether a user's email matched the password provided
        user = User.get_by_email(email)
        if user is not None:
            # check the password
            return user.password == password
        return False

    def get_id(self):
        return (self.user_id)

    # the second alternative is with @classmethod
    @classmethod
    def register(cls, fname, lname, username, email, password):
        user = cls.get_by_email(email)
        if user is None:
            new_user = cls(fname, lname, username, email, password)
            auth_token = new_user.encode_auth_token(new_user.user_id)
            new_user.save_to_mongo()
            # put the email of the user in a session variable
            # from flask import session
            session['email'] = email
            print(auth_token)
            return auth_token
        else:
            return None

    @staticmethod
    def login(user_email):
        # login_valid has already been called
        session['email'] = user_email


    @staticmethod
    def logout():
        session['email'] = None


    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=5),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'



    def json(self):


        return {
            "user_id": self.user_id,
            "fname": self.fname,
            "lname": self.lname,
            "uname": self.uname,
            "email": self.email,
            "password": self.password,
            "profile_pic": self.profile_pic,
            "bio": self.bio
        }


    def save_to_mongo(self):
        Database.insert(collection='users', data=self.json())