# directly import this model for models have a circle import issue. need copy to this into blue print folder. #Wei,shi
import uuid
import datetime
from flask import session, render_template
from app.common.database import Database
from flask_login import UserMixin
import jwt
import datetime
#from app import app, bc, mail
#from app.models.BlacklistToken import BlacklistToken
from flask_mail import Mail, Message

class User(UserMixin, object):

    # the main variable in user model
    def __init__(self, fname, lname, gender, phone, address, city, zipcode, state, uname, email, password, profile_pic=None, bio=None, user_id=None, _id=None, is_admin=False, is_email_verified=False):
        self.fname = fname
        self.lname = lname
        self.gender = gender
        self.phone = phone
        self.address = address
        self.city = city
        self.zip = zipcode
        self.state = state
        self.uname = uname
        self.email = email
        self.password = password
        self.profile_pic = 'default' if profile_pic is None else profile_pic
        self.bio = 'Hey this is ' + 'fname' if bio is None else bio
        self.user_id = int(str(uuid.uuid4().int)[:6]) if user_id is None else user_id
        self.is_admin = is_admin
        self.is_email_verified = is_email_verified

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

    def email_auth(self):
        print("Creating registration email")
        token = uuid.uuid4().hex
        links = ['http://ec2-3-19-30-128.us-east-2.compute.amazonaws.com/auth/verify_email/'+str(self.user_id)+'/'+token, 
                 'http://ec2-3-19-30-128.us-east-2.compute.amazonaws.com:5000/auth/verify_email/'+str(self.user_id)+'/'+token,
                 'http://127.0.0.1:5000/auth/verify_email/'+str(self.user_id)+'/'+token
        ]
        Database.insert(collection='email_token', data={'user_id':self.user_id, 'email_token':token})
        msg = Message('Verify Email', sender = 'ingenuity.senior@gmail.com', recipients = [self.email])
        msg.html = render_template('pages/verify_email.html', name=self.fname, links=links)
        mail.send(msg)
    # the second alternative is with @classmethod
    @classmethod
    def register(cls, fname, lname, gender, phone, address, city, zipcode, state, username, email, password, is_admin):
        user = cls.get_by_email(email)
        if user is None:
            new_user = cls(fname, lname, gender, phone, address, city, zipcode, state, username, email, password, is_admin)
            auth_token = new_user.encode_auth_token(new_user.user_id)
            new_user.email_auth()
            new_user.save_to_mongo()
            # put the email of the user in a session variable
            # from flask import session
            session['email'] = email
            print(auth_token)
            return new_user, auth_token
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
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=2, seconds=5),
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
            "gender": self.gender,
            "phone": self.phone,
            "address":self.address,
            "city": self.city,
            "zipcode": self.zip,
            "state": self.state,
            "uname": self.uname,
            "email": self.email,
            "password": self.password,
            "profile_pic": self.profile_pic,
            "bio": self.bio,
            "is_admin": self.is_admin,
            "is_email_verified": self.is_email_verified
        }


    def save_to_mongo(self):
        Database.insert(collection='users', data=self.json())

    @staticmethod
    def updatefname(uname,fname):
        Database.update_one(collection="users", query=[{'uname':uname}, {"$set": {"fname":fname }} ])
        
