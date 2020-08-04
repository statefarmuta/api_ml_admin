# -*- encoding: utf-8 -*-
"""
License: MIT
Copyright (c) 2019 Devi
"""

from flask_wtf          import FlaskForm
from flask_wtf.file     import FileField, FileRequired
from wtforms            import StringField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import InputRequired, Email, DataRequired

class LoginForm(FlaskForm):
	username    = StringField  (u'Username'        , validators=[DataRequired()])
	password    = PasswordField(u'Password'        , validators=[DataRequired()])

class RegisterForm(FlaskForm):
	name        = StringField  (u'Name'      , validators=[DataRequired()])
	lname 		= StringField  (u'Last Name' , validators=[DataRequired()])
	gender      = StringField  (u'Gender', validators=[DataRequired()])
	phone    	= StringField  (u'Phone', validators=[DataRequired()])
	address  	= StringField  (u'Address', validators=[DataRequired()])
	city     	= StringField  (u'City', validators=[DataRequired()])
	zipcode  	= StringField  (u'Zipcode', validators=[DataRequired()])
	state    	= StringField  (u'State' , validators=[DataRequired()])
	username    = StringField  (u'Username'  , validators=[DataRequired()])
	password    = PasswordField(u'Password'  , validators=[DataRequired()])
	email       = StringField  (u'Email'     , validators=[DataRequired(), Email()])


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Reset password')