#init version is created by Web application team, Wei Shi


from flask import render_template, flash, redirect, url_for, request
#from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from app.web import bp
from app.web.forms import LoginForm, RegistrationForm, changePasswordForm, updateProfileForm
from app.web.models.sessionuser import Session_User
import requests
from flask_session import Session
from flask import session
from app.web.models.user import User
from app.common.database import Database
from app import mongo

#return a index.html
@bp.route('/')
@bp.route('/index')
def index():
        return render_template('/index.html')
    

#user login, init version create by Devi.
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        #print('User Found')
        return render_template('/index.html', data=session['user'].name)
    form = LoginForm()
    jsonPayload = None
    if form.validate_on_submit():
        jsonPayload = {
                'username':form.username.data,
                'password':form.password.data
            }
        result = requests.post('http://0.0.0.0:5000/auth/login', json=jsonPayload)

        result = result.json()
        if result['status'] != 'fail':
            user = Session_User(form.username.data,result['auth_token'],result['user']['user_id'])
            
            session['user'] = user
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('web.mydashboard')
            return redirect(next_page)
        else:
            flash('Invalid username or password')
            return redirect(url_for('web.login'))
    return render_template('/login.html', title='Sign In', form=form)

#user log out, init version create by Devi.
@bp.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('web.index'))

#user register,
@bp.route('/register', methods=['GET','POST'])
def register():
    if 'user' in session:
        return redirect(url_for('web.mydashboard')) 
    form = RegistrationForm()
    jsonPayload = None
    if form.validate_on_submit():
        
        jsonPayload = {
                'username':form.username.data,
                'email':form.email.data,
                'password':form.password.data,
                'phone':form.phone.data,
                'name':form.fname.data,
                'lname':form.lname.data,
                'gender':form.gender.data,
                'address':form.address.data,
                'city':form.city.data,
                'zipcode':form.zipcode.data,
                'state':form.state.data  
            } 
        #print(jsonPayload)   
        result = requests.post('http://0.0.0.0:5000/auth/register', json=jsonPayload)
        
        result = result.json()
        if result['status'] == 'success':
            flash('Congratulations, you registered an account! Please verify your email first.')
            return redirect(url_for('web.login'))
        flash('The username or email have already registered.')
    return render_template('/register.html', title='Register', form=form)

#show dashboard
@bp.route('/mydashboard', methods=['GET'])
def mydashboard():
    if 'user' in session:
        return render_template('/mydashboard.html')
    else:
        return redirect(url_for('web.login'))
    
#show profile 
@bp.route('/myprofile', methods=['GET'])
def myprofile():
    if 'user' in session:
        userProfile = User.get_by_id(session['user'].uid)
        return render_template('/myprofile.html', user=userProfile)
    else:
        return redirect(url_for('web.login'))

#update profile
@bp.route('/edit_profile', methods=['GET','POST'])
def edit_profile():
    if 'user' in session:
        form = updateProfileForm()
        if form.validate_on_submit():
            Database.update_one(collection="users", query=[{'user_id':session['user'].uid}, \
                {"$set":{"uname":form.username.data,"fname":form.fname.data,"lname":form.lname.data,"bio":form.bio.data \
                    ,"phone":form.phone.data,"address":form.address.data,"city":form.city.data \
                        ,"zipcode":form.zipcode.data,"state":form.state.data}}])
            flash('Your profile has been updated.')
            #change session username to newone once update the database
            session['user'].name = form.username.data
            #print(session['user'].name)
            #return to myprofile page
            userProfile = User.get_by_id(session['user'].uid)
            return render_template('/myprofile.html', user=userProfile)
        elif request.method == 'GET':
            userProfile = User.get_by_id(session['user'].uid)
            form.username.data = userProfile.uname
            form.fname.data = userProfile.fname
            form.lname.data = userProfile.lname
            form.bio.data = userProfile.bio
            form.phone.data = userProfile.phone
            form.address.data = userProfile.address
            form.city.data = userProfile.city
            form.zipcode.data = userProfile.zip
            form.state.data = userProfile.state
        return render_template('/updateProfile.html', title='Update', form=form)
    else:
        return redirect(url_for('web.index'))

#change password
@bp.route('/change_password', methods=['GET','POST'])
def change_password():
    if 'user' in session:
        form = changePasswordForm()
        if form.validate_on_submit():
            Database.update_one(collection="users", query=[{'uname':session['user'].name},{"$set":{"password":form.password.data}}])
            flash('Your password has been changed.')
            userProfile = User.get_by_username(session['user'].name)
            return render_template('/myprofile.html', user=userProfile)
        return render_template('/changePassword.html', title='Change Password', form=form)
    else:
        return redirect(url_for('web.index'))

@bp.route('/request_file/<filename>')
def request_file(filename):
    return mongo.send_file(filename)

@bp.route('/uploader', methods=['GET','POST'])
def upload_file():
    if 'user' in session:
        if 'profile_pic' in request.files:
            profile_pic = request.files['profile_pic']
            mongo.save_file(profile_pic.filename, profile_pic)
            
            query = { 'uname':session['user'].name}
            updates = { "$set": { "profile_pic": profile_pic.filename } }
            mongo.db.users.update_one(query, updates)
            return redirect(url_for('web.myprofile'))
                
    else:
        return redirect(url_for('web.index'))


