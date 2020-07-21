from flask import Flask
from flask_migrate import Migrate
#from config import Config
from flask import Blueprint

bp = Blueprint('web', __name__, template_folder='templates')


#application = app # For beanstalk
#app.config.from_object(Config)

#app.secret_key = 'fegrweiugwoibgpiw40pt8940gtbuorwbgo408bg80pw4'
#app.config['SESSION_TYPE'] = 'filesystem'

from app.web import routes,errors
