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
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    phone = StringField('Phone Number', )
    fname = StringField('First Name', validators=[DataRequired()])
    lname = StringField('Last Name', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('male','male'), ('female','female')], validators=[DataRequired()])
    address = StringField('Address' )
    city = StringField('City')
    zipcode = StringField('Zipcode')
    state = StringField('State')
    submit = SubmitField('Register')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')
    
class changePasswordForm(FlaskForm):
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('Change')

class updateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    #email = StringField('email', validators=[DataRequired()])
    fname = StringField('First Name', validators=[DataRequired()])
    lname = StringField('Last Name', validators=[DataRequired()])
    bio = StringField('Bio')
    phone = StringField('Phone Number')
    address = StringField('Address' )
    city = StringField('City')
    zipcode = StringField('Zipcode')
    state = StringField('State')
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


    