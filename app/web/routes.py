#init version is created by Web application team, Wei Shi


from flask import render_template, flash, redirect, url_for, request
#from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from app.web import bp
from app.web.forms import LoginForm, RegistrationForm, changePasswordForm, updateProfileForm
from app.models.sessionuser import Session_User
import requests
from flask_session import Session
from flask import session
from app.web.user import User
from app.common.database import Database


@bp.route('/')
@bp.route('/index')
def index():
        return render_template('/index.html')
    


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
            user = Session_User(form.username.data,result['auth_token'])
            
            session['user'] = user
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('web.mydashboard')
            return redirect(next_page)
        else:
            flash('Invalid username or password')
            return redirect(url_for('web.login'))
    return render_template('/login.html', title='Sign In', form=form)


@bp.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('web.index'))


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


@bp.route('/mydashboard', methods=['GET'])
def mydashboard():
    if 'user' in session:
        return render_template('/mydashboard.html')
    else:
        return redirect(url_for('web.login'))
    
   
@bp.route('/myprofile', methods=['GET'])
def myprofile():
    if 'user' in session:
        userProfile = User.get_by_username(session['user'].name)
        return render_template('/myprofile.html', user=userProfile)
    else:
        return redirect(url_for('web.login'))

@bp.route('/edit_profile', methods=['GET','POST'])
def edit_profile():
    if 'user' in session:
        form = updateProfileForm()
        if form.validate_on_submit():
            Database.update_one(collection="users", query=[{'uname':session['user'].name}, \
                {"$set":{"fname":form.fname.data,"lname":form.lname.data,"bio":form.bio.data \
                    ,"phone":form.phone.data,"address":form.address.data,"city":form.city.data \
                        ,"zipcode":form.zipcode.data,"state":form.state.data}}])
            flash('Your profile has been updated.')
            userProfile = User.get_by_username(session['user'].name)
            return render_template('/myprofile.html', user=userProfile)
        return render_template('/updateProfile.html', title='Update', form=form)
    else:
        return redirect(url_for('web.index'))


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