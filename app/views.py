# -*- encoding: utf-8 -*-
"""
License: MIT
Copyright (c) 2019 - Devi
"""

# Python modules
import os, logging 
import uuid
import datetime


# Flask modules
from flask               import Blueprint, render_template, make_response, jsonify, request, url_for, redirect, send_from_directory
from flask_login         import login_user, logout_user, current_user, login_required
from werkzeug.exceptions import HTTPException, NotFound, abort
from werkzeug.utils import secure_filename

# App modules
from app        import app, lm, db, bc, r, q
from app.models.user import User
from app.models.project import Project
from app.models.business_logic.test import Analysis
from app.forms  import LoginForm, RegisterForm
from app.common.database import Database
from app.auth import RegisterAPI, LoginAPI, LogoutAPI, UserAPI
from app.models.BlacklistToken import BlacklistToken
from app.models.tasks import DLModel

from flask_swagger_ui import get_swaggerui_blueprint
from flask_restful_swagger import swagger
from flask_restful import Resource, Api



# provide login manager with load_user callback
@lm.user_loader
def load_user(user_id):
    return User.get_by_id(int(user_id))

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
swagger_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': 'Sate Farm API end point Docs by Devi'
    }
)

app.register_blueprint(swagger_blueprint, url_prefix=SWAGGER_URL)

# Logout user
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# Register a new user
@app.route('/register', methods=['GET', 'POST'])
def register():
    
    # cut the page for authenticated users
    if current_user.is_authenticated:
        return redirect(url_for('index'))
            
    # declare the Registration Form
    form = RegisterForm(request.form)

    msg = None

    if request.method == 'GET': 

        return render_template( 'pages/auth-register.html', form=form, msg=msg )

    # check if both http method is POST and form is valid on submit
    if form.validate_on_submit():

        # assign form data to variables
        fname    = request.form.get('name'    , '', type=str)
        lname    = request.form.get('lname'   , '', type=str) 
        gender   = request.form.get('gender' ,'', type=str)
        phone    = request.form.get('phone' ,'', type=str)
        address  = request.form.get('address' ,'', type=str)
        city     = request.form.get('city' ,'', type=str)
        zipcode  = request.form.get('zipcode' ,'', type=str)
        state    = request.form.get('state' ,'', type=str)
        username = request.form.get('username', '', type=str)
        password = request.form.get('password', '', type=str) 
        email    = request.form.get('email'   , '', type=str) 

        # filter User out of database through username
        user = User.get_by_username(username)

        # filter User out of database through username
        user_by_email = User.get_by_email(email)

        if user or user_by_email:
            msg = 'Error: User exists!'
        
        else:         

            pw_hash = password #bc.generate_password_hash(password)
        
            user = User.register(fname=fname, lname=lname, gender=gender, phone=phone, 
                                 address=address, city=city, zipcode=zipcode, state=state, 
                                 username=username, email=email, password=pw_hash, is_admin=True)

            msg = 'User created, please <a href="' + url_for('login') + '">login</a>'     

    else:
        msg = 'Input error'     

    return redirect(url_for('login'))

# Authenticate user
@app.route('/login', methods=['GET', 'POST'])
def login():
    
    # cut the page for authenticated users
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # Declare the login form
    form = LoginForm(request.form)

    # Flask message injected into the page, in case of any errors
    msg = None

    # check if both http method is POST and form is valid on submit
    if form.validate_on_submit():

        # assign form data to variables
        username = request.form.get('username', '', type=str)
        password = request.form.get('password', '', type=str) 

        # filter User out of database through username
        user = User.get_by_username(username)

        if user:
            #if bc.check_password_hash(user.password, password):
            if user.password == password and user.is_admin:
                print("password matched")
                login_user(user)
                Database.insert(collection="login_log", data={
                    "user_name":username, 
                    "date_time":str(datetime.datetime.utcnow()), 
                    "ip":request.remote_addr
                    }
                )
                return redirect(url_for('index'))
            else:
                msg = "Wrong password or not Admin. Please try again."
        else:
            msg = "Unknown user"

    return render_template( 'pages/auth-login.html', form=form, msg=msg )


# Authenticate user
@app.route('/create_project', methods=['POST'])
def create_project():
    
    if not current_user.is_authenticated:
        print('not logged in')
        return redirect(url_for('login'))

    data = Project.from_user(current_user.user_id)

    all_data = []
    html = None
    project_id = None
    titles = None
    

    if request.method == 'POST':
        f_1 = request.files['file_1']
        f_2 = request.files['file_2']

        filename_one = str(uuid.uuid4())[:8]+"."+f_1.filename.rsplit('.', 1)[1].lower()
        if not f_2:
            f_2 = f_1

        filename_two = str(uuid.uuid4())[:8]+"."+f_2.filename.rsplit('.', 1)[1].lower()
        f_1.save(app.config['UPLOAD_FOLDER']+"dataset/"+secure_filename(filename_one))
        f_2.save(app.config['UPLOAD_FOLDER']+"dataset/"+secure_filename(filename_two))

        dataset = [
                   {'name':filename_one, 'type':'Forecasting Timeseries Data', 'file_attributes':[0,0], 'datasetID':filename_one, 'status':'Active'}, 
                   {'name':filename_two, 'type':'Item Attributes', 'file_attributes':[0,0], 'datasetID':filename_two, 'status':'Active'}
                  ]
        pname = request.form['pname']
        ptype = request.form['ptype']
        user_id = current_user.user_id
        project_id = int(str(uuid.uuid4().int)[:6])
        date = str(datetime.datetime.utcnow())

        #project_id, user_id, pname, ptype, dataset, date
        new_project = Project(project_id, user_id, pname, ptype, dataset, date)
        new_project.save_to_mongo()


        return redirect(url_for('project_dashboard', project_id=project_id))

        # return render_template( 'pages/project.html', data=data, all_data=all_data, tables=html, titles=titles )

@app.route('/create_project_sample/<customer_name>', methods=['POST'])
def create_project_sample(customer_name, user_id=None):
    
    if not current_user.is_authenticated:
        if user_id is None:
            print('not logged in')
            return redirect(url_for('login'))

    if request.method == 'POST':

        dataset = [
                   {'name':'sample.csv', 'type':'Forecasting Timeseries Data', 'file_attributes':[0,0], 'datasetID':'sample.csv', 'status':'Active'}, 
                   {'name':'sample.csv', 'type':'Item Attributes', 'file_attributes':[0,0], 'datasetID':'sample1.csv', 'status':'Active'}, 
                  ]
        pname = customer_name
	#if pname is None or len(pname) == 0:
           # pname = "Sample"

        ptype = "Forecasting"
        project_id = int(str(uuid.uuid4().int)[:6])
        date = str(datetime.datetime.utcnow())

        #project_id, user_id, pname, ptype, dataset, date
        new_project = Project(project_id, user_id, pname, ptype, dataset, date)
        new_project.save_to_mongo()


        return redirect(url_for('project_dashboard', project_id=project_id))




@app.route('/dataset_raw_data/<project_id>/<dataset_id>', methods=['GET'])
@app.route('/dataset_raw_data/<project_id>/<dataset_id>/', methods=['GET'])
def dataset_raw_data(project_id, dataset_id):
    if not current_user.is_authenticated:
        print('not logged in')
        return redirect(url_for('login'))

    content = None
    data = None
    data = Project.from_user(current_user.user_id)
    if Project.check_auth(current_user.user_id, int(project_id)):
        project_specific_data = Project.get_one(current_user.user_id, int(project_id))
        print(project_specific_data)

    table_html, titles = Analysis.get_data_head(app.config['UPLOAD_FOLDER'] + 'dataset/' + dataset_id)

    try:
        # try to match the pages defined in -> pages/<input file>
        return render_template( 'pages/raw_data.html', data=data, project_specific_data=project_specific_data, tables=table_html, titles=titles, active_dataset=dataset_id)
    
    except:
        
        return render_template( 'pages/error-404.html' )


@app.route('/explore_data/<project_id>/<dataset_id>', methods=['GET'])
@app.route('/explore_data/<project_id>/<dataset_id>/', methods=['GET'])
def explore_data(project_id, dataset_id):
    if not current_user.is_authenticated:
        print('not logged in')
        return redirect(url_for('login'))

    content = None
    data = None
    data = Project.from_user(current_user.user_id)
    if Project.check_auth(current_user.user_id, int(project_id)):
        project_specific_data = Project.get_one(current_user.user_id, int(project_id))

    table_data, titles, numerical_vals = Analysis.get_coloums_stat(app.config['UPLOAD_FOLDER'] + 'dataset/' +dataset_id)

    try:
        # try to match the pages defined in -> pages/<input file>
        return  render_template( 'pages/explore_data.html', data=data, project_specific_data=project_specific_data, numerical_vals=numerical_vals, table_data=table_data, titles=titles, active_dataset=dataset_id)
    
    except:
        
        return render_template( 'pages/error-404.html' )



@app.route('/dataset_schema/<project_id>', methods=['GET'])
@app.route('/dataset_schema/<project_id>/', methods=['GET'])
def dataset_schema(project_id):
    if not current_user.is_authenticated:
        print('not logged in')
        return redirect(url_for('login'))

    content = None
    data = None
    data = Project.from_user(current_user.user_id)
    if Project.check_auth(current_user.user_id, int(project_id)):
        project_specific_data = Project.get_one(current_user.user_id, int(project_id))
        print(project_specific_data)


    try:
        # try to match the pages defined in -> pages/<input file>
        return render_template( 'pages/dataset_schema.html', data=data, project_specific_data=project_specific_data)
    
    except:
        
        return render_template( 'pages/error-404.html' )




@app.route('/metric_dashboard/<project_id>', methods=['GET'])
@app.route('/metric_dashboard/<project_id>/', methods=['GET'])
def metric_dashboard(project_id):
    if not current_user.is_authenticated:
        print('not logged in')
        return redirect(url_for('login'))

    content = None
    data = None
    
    model_info = None

    data = Project.from_user(current_user.user_id)
    if Project.check_auth(current_user.user_id, int(project_id)):
        project_specific_data = Project.get_one(current_user.user_id, int(project_id))


    if project_specific_data[0]['model_available']:
        model_info = Database.find_one(collection="models", query={"project_id":project_specific_data[0]['project_id']})

    print(model_info)


    try:
        # try to match the pages defined in -> pages/<input file>
        return  render_template( 'pages/metric_dashboard.html', data=data, project_specific_data=project_specific_data, model_info=model_info)
    
    except:
        
        return render_template( 'pages/error-404.html' )




@app.route('/predictions_dashboard/<project_id>', methods=['GET'])
@app.route('/predictions_dashboard/<project_id>/', methods=['GET'])
def predictions_dashboard(project_id):
    if not current_user.is_authenticated:
        print('not logged in')
        return redirect(url_for('login'))

    content = None
    data = None

    model_info = None

    data = Project.from_user(current_user.user_id)
    if Project.check_auth(current_user.user_id, int(project_id)):
        project_specific_data = Project.get_one(current_user.user_id, int(project_id))

    if project_specific_data[0]['model_available']:
        model_info = Database.find_one(collection="models", query={"project_id":project_specific_data[0]['project_id']})

    print(model_info)


    try:
        # try to match the pages defined in -> pages/<input file>
        return  render_template( 'pages/prediction_dashboard.html', data=data, project_specific_data=project_specific_data, model_info=model_info)
    
    except:
        
        return render_template( 'pages/error-404.html' )



@app.route('/project_dashboard', methods=['GET'])
@app.route('/project_dashboard/', methods=['GET'])
def project_default():
    return redirect(url_for('index'))



@app.route('/project_dashboard/<project_id>', methods=['GET'])
@app.route('/project_dashboard/<project_id>/', methods=['GET'])
def project_dashboard(project_id):
    if not current_user.is_authenticated:
        print('not logged in')
        return redirect(url_for('login'))

    content = None
    data = None
    data = Project.from_user(current_user.user_id)

    project_specific_data = []
    html = None
    titles = None

    model_info = None
    if Project.check_auth(current_user.user_id, int(project_id)):
        project_specific_data = Project.get_one(current_user.user_id, int(project_id))
        print(project_specific_data)


    if project_specific_data[0]['model_available']:
        model_info = Database.find_one(collection="models", query={"project_id":project_specific_data[0]['project_id']})
    
    print(model_info)

    try:
        # try to match the pages defined in -> pages/<input file>
        return render_template( 'pages/project_dashboard.html', data=data, project_specific_data=project_specific_data, model_info=model_info)
    
    except:
        
        return render_template( 'pages/error-404.html' )


@app.route('/auth/customer_dashboard/<project_id>', methods=['GET'])
@app.route('/auth/customer_dashboard/<project_id>/', methods=['GET'])
def customer_dashboard(project_id):
    if not current_user.is_authenticated:
        print('not logged in')
        return redirect(url_for('login'))

    content = None
    data = None
    data = Project.from_user(current_user.user_id)

    project_specific_data = []
    html = None
    titles = None

    model_info = None
    if Project.check_auth(current_user.user_id, int(project_id)):
        project_specific_data = Project.get_one(current_user.user_id, int(project_id))
        print(project_specific_data)


    if project_specific_data[0]['model_available']:
        model_info = Database.find_one(collection="models", query={"project_id":project_specific_data[0]['project_id']})
    
    print(model_info)

    try:
        # try to match the pages defined in -> pages/<input file>
        responseObject = {
                "data":data, 
                "project_specific_data":project_specific_data, 
                "model_info":model_info
            }
        return make_response(jsonify(responseObject)), 201
    
    except:
        responseObject = {
                'status': 'fail',
                'message': 'Some error occurred with database. Please try again.'
                }
        return make_response(jsonify(responseObject)), 201


@app.route('/train_model/<project_id>', methods=['GET'])
@app.route('/train_model/<project_id>/', methods=['GET'])
def start_train(project_id):
    if not current_user.is_authenticated:
        print('not logged in')
        return redirect(url_for('login'))
    
    

    content = None
    data = None
    data = Project.from_user(current_user.user_id)

    project_specific_data = []
    html = None
    titles = None

    if Project.check_auth(current_user.user_id, int(project_id)):
        project_specific_data = Project.get_one(current_user.user_id, int(project_id))
        if project_specific_data[0]['model_available']:
            return jsonify(result='trained')
        q.enqueue(DLModel.train_model, project_specific_data[0]['dataset'][0]['name'], int(project_id), app.config['UPLOAD_FOLDER'])
        Database.update_one(collection='projects', query=[{'project_id':int(project_id)}, { "$set": { "in_training": True } } ])
        return jsonify(result='done')
    else:
        return jsonify(result='error')


# App main route + generic routing
@app.route('/', defaults={'path': 'index_new.html'})
@app.route('/<path>')
def index(path):

    if not current_user.is_authenticated:
        print('not logged in')
        return redirect(url_for('login'))

    content = None
    data = None
    data = Project.from_user(current_user.user_id)
    print(data)
    
    try:
        # try to match the pages defined in -> pages/<input file>
        return render_template( 'pages/'+path, data=data)
    
    except:
        
        return "404 Not Found"

# Return sitemap 
@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'sitemap.xml')

@app.route('/auth/verify_email/<user_id>/<email_token>', methods=['GET'])
@app.route('/auth/verify_email/<user_id>/<email_token>/', methods=['GET'])
def auth_verify_email(user_id, email_token):
    user = User.get_by_id(int(user_id))
    if user.is_email_verified:
        responseObject = {
            'status': 'fail',
            'message': 'Email already verified'
        }
        return make_response(jsonify(responseObject)), 202
    
    email_auth_data = Database.find_one(collection='email_token', query={'user_id': int(user_id)})
    if email_auth_data['email_token'] == email_token:
        Database.update_one(collection="users", query=[{'user_id': int(user_id)}, {"$set": { "is_email_verified": True }} ])
        responseObject = {
            'status': 'success',
            'message': 'Email verified'
        }
        return make_response(jsonify(responseObject)), 201

# add Rules for API Endpoints
@app.route('/auth/register', methods=['POST'])
def auth_register():

    # get the post data
    post_data = request.get_json()
    if post_data is None:
        post_data = post_data.form
    # check if user already exists
    
    # filter User out of database through username
    user = User.get_by_username(post_data.get('username'))

    # filter User out of database through username
    user_by_email = User.get_by_email(post_data.get('email'))

    if not user and not user_by_email :
        try:
            pw_hash = post_data.get('password') #bc.generate_password_hash(password)
            user, user_auth = User.register(post_data.get('name'), post_data.get('lname'), 
                                 post_data.get('gender'), post_data.get('phone'),
                                 post_data.get('address'), post_data.get('city'),
                                 post_data.get('zipcode'), post_data.get('state'),
                                 post_data.get('username'), post_data.get('email'), 
                                 pw_hash, post_data.get('is_admin'))

            # # insert the user
            # db.session.add(user)
            # db.session.commit()
            # generate the auth token
            print(user)
            user_dict = user.json()
            responseObject = None
            if user:
                print(user.user_id)
                create_project_sample(post_data.get('name'), user.user_id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': user_auth.decode(),
                    'user': user_dict
                }
                return make_response(jsonify(responseObject)), 201
            else:
                responseObject = {
                'status': 'fail',
                'message': 'Some error occurred with database. Please try again.'
                }
                return make_response(jsonify(responseObject)), 500

        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Some error occurred. Please try again.'
            }
            print(e)
            return make_response(jsonify(responseObject)), 401
    else:
        responseObject = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return make_response(jsonify(responseObject)), 202

@app.route('/auth/login', methods=['POST'])
def auth_login():
    # get the post data
    post_data = request.get_json()
    if post_data is None:
        post_data = request.form
    
    try:
        # fetch the user data
        user = User.get_by_username(post_data.get('username'))
        user_dict = user.json()
        if user and user.password == post_data.get('password') and user.is_email_verified:
            auth_token = user.encode_auth_token(user.user_id)
            if auth_token:
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully logged in.',
                    'auth_token': auth_token.decode(),
                    'user': user_dict
                }
                return make_response(jsonify(responseObject)), 201
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User does not exist or not verified.'
            }
            return make_response(jsonify(responseObject)), 404
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Try again'
        }
        return make_response(jsonify(responseObject)), 500


@app.route('/auth/status', methods=['GET'])
def user_view():
    # get the auth token
    auth_header = request.headers.get('Authorization')
    data = request.get_json()
    if data is None:
        data = request.form
    if auth_header:
        try:
            auth_token = auth_header.strip()
        except IndexError:
            responseObject = {
                'status': 'fail',
                'message': 'Bearer token malformed.'
            }
            return make_response(jsonify(responseObject)), 401
    else:
        auth_token = ''
    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            user = User.get_by_id(resp)
            stats = Database.find_one(collection='user_stats', query={'user_id':resp, 'date':data.get('date')})
            responseObject = {
                'status': 'success',
                'data': {
                    'user_id': user.user_id,
                    'email': user.email,
                    'fname': user.fname,
                    'lname': user.lname
                },
                'user_stats': stats
            }
            return make_response(jsonify(responseObject)), 200
        responseObject = {
            'status': 'fail',
            'message': resp
        }
        return make_response(jsonify(responseObject)), 401
    else:
        responseObject = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return make_response(jsonify(responseObject)), 401




@app.route('/auth/user_info', methods=['GET', 'POST'])
def user_info():
    # get the auth token
    auth_header = request.headers.get('Authorization')
    if auth_header:
        try:
            auth_token = auth_header.strip()
        except IndexError:
            responseObject = {
                'status': 'fail',
                'message': 'Bearer token malformed.'
            }
            return make_response(jsonify(responseObject)), 401
    else:
        auth_token = ''
    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            user = User.get_by_id(resp)
            responseObject = {
                'status': 'success',
                'data': user.json()
            }
            return make_response(jsonify(responseObject)), 200
        responseObject = {
            'status': 'fail',
            'message': resp
        }
        return make_response(jsonify(responseObject)), 401
    else:
        responseObject = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return make_response(jsonify(responseObject)), 401



@app.route('/auth/logout', methods=['POST'])
def auth_logout():
    # get auth token
    auth_header = request.headers.get('Authorization')
    print(auth_header)
    print(request.headers)
    if auth_header:
        auth_token = auth_header #.split(" ")[1]
    else:
        auth_token = ''
    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            # mark the token as blacklisted
            blacklist_token = BlacklistToken(token=auth_token)
            try:
                # insert the token
                blacklist_token.save_to_mongo()
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully logged out.'
                }
                return make_response(jsonify(responseObject)), 200
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': e
                }
                return make_response(jsonify(responseObject)), 200
        else:
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
    else:
        responseObject = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return make_response(jsonify(responseObject)), 403

