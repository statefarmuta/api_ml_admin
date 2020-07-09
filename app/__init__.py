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


# Redis
import redis
from rq import Queue

# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

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
