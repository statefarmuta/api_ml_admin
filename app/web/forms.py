from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.common.database import Database
from flask_session import Session 
from flask import session



class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    #remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    phone = StringField('phone', )
    fname = StringField('fname', validators=[DataRequired()])
    lname = StringField('lname', validators=[DataRequired()])
    gender = SelectField('gender', choices=[('male','male'), ('female','female')], validators=[DataRequired()])
    address = StringField('address' )
    city = StringField('city')
    zipcode = StringField('zipcode')
    state = StringField('state')
    submit = SubmitField('register')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')
    
class changePasswordForm(FlaskForm):
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('Change')

class updateProfileForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    #email = StringField('email', validators=[DataRequired()])
    fname = StringField('fname', validators=[DataRequired()])
    lname = StringField('lname', validators=[DataRequired()])
    bio = StringField('bio')
    phone = StringField('phone')
    address = StringField('address' )
    city = StringField('city')
    zipcode = StringField('zipcode')
    state = StringField('state')
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != session['user'].name:
            user = Database.find_one(collection ="users", query={'uname':username.data})
            print(user)
            if user is not None:
                raise ValidationError('Please use a different username.')

    #def validate_email(self, email):
    #    user = Database.find_one(collection ="users", query={'email':email.data})
    #    if user is not None:
    #        raise ValidationError('Please use a different email address.')