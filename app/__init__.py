# -*- encoding: utf-8 -*-
"""
License: MIT
Copyright (c) 2019 - Devi
"""

import os

from flask                  import Flask
from flask_sqlalchemy       import SQLAlchemy
from flask_login            import LoginManager
from flask_bcrypt           import Bcrypt
from app.common.database    import Database
from flask_mail             import Mail, Message

#### blueprint
from flask import Blueprint
from flask_session import Session
from flask import session
from flask_pymongo import PyMongo
#### blueprint

# Redis
import redis
from rq import Queue

# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
mail= Mail(app)

####blueprint
app.secret_key = 'fegrweiugwoibgpiw40pt8940gtbuorwbgo408bg80pw4'
app.config['SESSION_TYPE'] = 'filesystem'
sess = Session()
sess.init_app(app)
app.config['MONGO_DBNAME'] = 'novutree'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/novutree'
mongo = PyMongo(app)
from app.web import bp as web_bp
app.register_blueprint(web_bp,url_prefix='/web')
####blueprint


app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'teamaerouta@gmail.com'
app.config['MAIL_PASSWORD'] = 'Statefarm@123'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

app.config['HOST'] = "ec2-54-214-218-104.us-west-2.compute.amazonaws.com"

app.config['SECRET_KEY'] = 'GEOE4947tvfi939gf3v9e'
app.config.from_object('app.configuration.Config')
app.config['UPLOAD_FOLDER']	= '/home/novutree/novutree_ui/app/static/uploads/'
db = SQLAlchemy  (app) # flask-sqlalchemy
bc = Bcrypt      (app) # flask-bcrypt

lm = LoginManager(   ) # flask-loginmanager
lm.init_app(app) # init the login manager

r = redis.Redis()
q = Queue(connection = r, default_timeout=36000)

# Setup database
@app.before_first_request
def initialize_database():
    Database.initialize()

# Import routing, models and Start the App
from app import views, models
