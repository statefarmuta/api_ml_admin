# init version is created by Web application team, Wei Shi

from datetime import date, timedelta
import datetime
from flask import render_template, flash, redirect, url_for, request, jsonify
#from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from app.web import bp
from app.web.forms import LoginForm, RegistrationForm, changePasswordForm, updateProfileForm,  RequestResetForm
from app.web.models.sessionuser import Session_User
import requests
from flask_session import Session
from flask import session
from app.web.models.user import User
from app.common.database import Database
from app import mongo
import os
import boto3
import pandas as pd


def retrieveFitbitSummary(date):
    file = open("aws.txt")
    text = file.readlines()
    sname=""
    reg_name=""
    access_key=""
    secret_key=""

    for line in text:
        line = line.rstrip("\n")
        linetokens = list(line.split(","))
        sname=str(linetokens[0])
        reg_name=str(linetokens[1])
        access_key=str(linetokens[2])
        secret_key=str(linetokens[3])


    s3 = boto3.resource(
        service_name=sname,
        region_name=reg_name,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    try:
        queryString = 'Date_'+date+'_User_id_218817_fitbitdata.csv'
        obj = s3.Bucket('mobilebucket').Object(queryString).get()
    except:

        Summary = [[0], [0], [0], [0], [0], [0]]
        return Summary

    obj = s3.Bucket('mobilebucket').Object(queryString).get()
    foo = pd.read_csv(obj['Body'])
    idd, activeScore, efficiency, restingHeartRate, OutOfRange, caloriesOut = 0, 0, 0, 0, 0, 0
    for index, row in foo.iterrows():

        idd = row['ID']
        activeScore = row['activeScore']
        efficiency = row['efficiency']
        restingHeartRate = row['restingHeartRate']
        OutofRange = ['(Out of Range)']
        caloriesOut = row['caloriesOut']
        SleepData = row['totalMinutesAsleep']

    Summary = [idd, activeScore, efficiency,
               restingHeartRate, OutOfRange, caloriesOut, SleepData]
    return Summary


def retrieveHourlyData(date):
    file = open("aws.txt")
    text = file.readlines()
    sname=""
    reg_name=""
    access_key=""
    secret_key=""

    for line in text:
        line = line.rstrip("\n")
        linetokens = list(line.split(","))
        sname=str(linetokens[0])
        reg_name=str(linetokens[1])
        access_key=str(linetokens[2])
        secret_key=str(linetokens[3])


    s3 = boto3.resource(
        service_name=sname,
        region_name=reg_name,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    try:
        queryString = 'Date_'+date+'_User_id_218817_hourlydata.csv'
        obj = s3.Bucket('mobilebucket').Object(queryString).get()
    except:
        HourlyData = [[0], [0], [0], [0], [0], [0], [0], [0], [0], [0]]
        return HourlyData

       # read hourly data file. each line of data is in 15 minute increments
    queryString = 'Date_'+date+'_User_id_218817_hourlydata.csv'

    obj = s3.Bucket('mobilebucket').Object(queryString).get()
    foo = pd.read_csv(obj['Body'])
    calories = []
    steps = []
    distance = []
    floors = []
    elevation = []
    veryActiveMinutes = []
    lightlyActiveMinutes = []
    sedentaryMinutes = []
    fairlyActiveMinutes = []
    heartRate = []

    for index, row in foo.iterrows():

        calories.append(row['calories'])
        steps.append(row['steps'])
        distance.append(row['distance'])
        floors.append(row['floors'])
        elevation.append(row['elevation'])
        veryActiveMinutes.append(row['minutesVeryActive'])
        lightlyActiveMinutes.append(row['minutesLightlyActive'])
        sedentaryMinutes.append(row['minutesSedentary'])
        fairlyActiveMinutes.append(row['minutesFairlyActive'])
        heartRate.append(row['heartRate'])

    hourlyCalories = []
    hourlySteps = []
    hourlyDistance = []
    hourlyFloors = []
    hourlyElevation = []
    hourlyHeartRate = []

    # conversions from data in increments of 15 minutes to hourly data
    for x in range(0, 95, 4):
        hourlyCalories.append(
            calories[x]+calories[x+1]+calories[x+2]+calories[x+3])
        hourlySteps.append(steps[x]+steps[x+1]+steps[x+2]+steps[x+3])
        hourlyDistance.append(
            distance[x]+distance[x+1]+distance[x+2]+distance[x+3])
        hourlyFloors.append(floors[x]+floors[x+1]+floors[x+2]+floors[x+3])
        hourlyElevation.append(
            elevation[x]+elevation[x+1]+elevation[x+2]+elevation[x+3])
        hourlyHeartRate.append(
            (heartRate[x]+heartRate[x+1]+heartRate[x+2]+heartRate[x+3])/4)
    lightlyActiveMinutes = lightlyActiveMinutes[0]
    sedentaryMinutes = sedentaryMinutes[0]
    fairlyActiveMinutes = fairlyActiveMinutes[0]
    veryActiveMinutes = veryActiveMinutes[0]

    todayData = [hourlyCalories, hourlySteps, hourlyDistance,
                 hourlyFloors, hourlyElevation, sedentaryMinutes, lightlyActiveMinutes, veryActiveMinutes, fairlyActiveMinutes]
    todayData.append(hourlyHeartRate)
    return todayData


def retrieveSleepData(date):

    file = open("aws.txt")
    text = file.readlines()
    sname=""
    reg_name=""
    access_key=""
    secret_key=""

    for line in text:
        line = line.rstrip("\n")
        linetokens = list(line.split(","))
        sname=str(linetokens[0])
        reg_name=str(linetokens[1])
        access_key=str(linetokens[2])
        secret_key=str(linetokens[3])


    s3 = boto3.resource(
        service_name=sname,
        region_name=reg_name,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    Sleep = [0, 0, 0, 0]
    # read sleepdata file.
    try:
        queryString = 'Date_'+date+'_User_id_218817_sleepdata.csv'
        obj = s3.Bucket('mobilebucket').Object(queryString).get()
    except:
        Sleep = [[0], [0], [0], [0]]
        return Sleep
    queryString = 'Date_'+date+'_User_id_218817_sleepdata.csv'
    obj = s3.Bucket('mobilebucket').Object(queryString).get()
    foo = pd.read_csv(obj['Body'])
    for index, row in foo.iterrows():

        level = row['level']
        seconds = row['seconds']
        if level == 'wake':
            Sleep[0] = Sleep[0]+seconds

        elif level == 'light':
            Sleep[1] = Sleep[1]+seconds
        elif level == 'deep':
            Sleep[2] = Sleep[2]+seconds
        elif level == 'rem':
            Sleep[3] = Sleep[3]+seconds
    for x in range(len(Sleep)):
        Sleep[x] = round((Sleep[x]/3600), 2)

    return Sleep


# this function sums up the hourly daily for each attribute
def HourlyToDaily(HourlyData):
    DailyCalories = sum(HourlyData[0])
    DailySteps = sum(HourlyData[1])
    DailyDistance = sum(HourlyData[2])
    DailyFloors = sum(HourlyData[3])
    DailyElevation = sum(HourlyData[4])
    DailyHeartRate = sum(HourlyData[9])
    DailyHeartRate = round(DailyHeartRate/24)

    DailyData = [DailyCalories, DailySteps, DailyDistance,
                 DailyFloors, DailyElevation, HourlyData[5], HourlyData[6], HourlyData[7], HourlyData[8], DailyHeartRate]
    return DailyData

# return a index.html


@bp.route('/')
@bp.route('/index')
def index():
    return render_template('/index.html')


# this function gets the current week's data
@bp.route('/weekdata', methods=['POST'])
def GetWeekData():

    # get the current date
    day = date.today()
    day = day-timedelta(days=7)
    start = 0
    WeeklySummary = []
    WeeklySleep = []
    WeeklyHourly = []
    Dates = []

    # iterates backwards 1 weeek and call each method to collect that day's particular metric
    for x in range(8):
        day = day+timedelta(days=start)
        datee = day.strftime("%Y-%m-%d")
        # call methods to get our daily data
        DailySummary = retrieveFitbitSummary(datee)
        DailySleep = retrieveSleepData(datee)
        DailyHourly = retrieveHourlyData(datee)
        # convert data from 1 hr increments to 24 hour increments
        Daily = HourlyToDaily(DailyHourly)

        WeeklySummary.append(DailySummary)
        WeeklySleep.append(DailySleep)
        WeeklyHourly.append(Daily)
        start = 1
        Dates.append(datee)

        # get our fitbitsummary data

    WeeklyData = {'WeeklySummary': WeeklySummary, 'WeeklySleep': WeeklySleep,
                  'WeeklyHourly': WeeklyHourly, 'Dates': Dates}

    return WeeklyData


# this request handles the date function
@bp.route('/datedata', methods=['POST'])
def GetDateData():
    user_id = 123
    # convert our data from a form object to a dictionary object
    data = request.form.to_dict(flat=False)
    # get our date data from our dictionary
    StartDate = data['Start[]']
    StartDate = StartDate[0]
    EndDate = data['End[]']
    EndDate = EndDate[0]
    # Parse our dates since we need to create a Date object for these dates
    EndYear, EndMonth, EndDay = EndDate[0:4], EndDate[5:7], EndDate[8:10]
    StartYear, StartMonth, StartDay = StartDate[0:
                                                4], StartDate[5:7], StartDate[8:10]
    # create our Date objects
    StartDate = datetime.date(int(StartYear), int(StartMonth), int(StartDay))
    EndDate = datetime.date(int(EndYear), int(EndMonth), int(EndDay))
    diff = EndDate - StartDate
    todayData = {'steps': [], 'calories': [], 'heart_rate': [], 'rating': [
    ], 'hours_slept': 0, 'steps_climbed': 0, 'Number_Days': 0}
    # go through each day in between our 2 dates and collect the data
    todayData['Number_Days'] = diff.days+1
    # read i files between the start and end dates
    SleepData = []
    Summary = []
    Daily = []
    Dates = []
    for i in range(diff.days + 1):
        # create the string we will use to lookup the data for that particular date
        CurrentDay = StartDate + datetime.timedelta(i)
        SleepData.append(retrieveSleepData(str(CurrentDay)))
        Summary.append(retrieveFitbitSummary(str(CurrentDay)))
        HourlyData = retrieveHourlyData(str(CurrentDay))
        DailyData = HourlyToDaily(HourlyData)
        Daily.append(DailyData)
        datee = CurrentDay.strftime("%Y-%m-%d")
        Dates.append(datee)
    todayData = {'SleepData': SleepData,
                 'Summary': Summary, 'Daily': Daily, 'Dates': Dates}
    return todayData


# this request handles any updated data
@bp.route('/data', methods=['GET'])
def updateData():
    today = date.today()
    todayData = mongo.db.user_stats.find_one(
        {'user_id': session['user'].uid, 'date': today.strftime("%Y-%m-%d")})
    # read our data file to get data
    #user_id = 123
    user_id = session['user'].uid
    file_String = "HealthData/"+str(user_id)+"_"+str(today)+".txt"
    file = open("123_data.txt")
    #file = open(file_String)
    text = file.readlines()
    if todayData is None:
        todayTotal = [0, 0, 0, 0]
        todayData = {'hours': [],
                     'calories': [],
                     'caloriesBMR': [],
                     'steps': [],
                     'distance': [],
                     'floors': [],
                     'elevation': [],
                     'minutesSedentary': 0,
                     'minutesLightlyActive': 0,
                     'minutesFairlyActive': 0,
                     'minutesVeryActive': 0
                     }

        counter = 0
        # go through each line in our data file
        for line in text:
            # make sure we only read the 2nd row and on
            # since the first row contains the "attributes" of our data
            if counter != 0:
                line = line.rstrip("\n")
                linetokens = list(line.split(","))
                todayData['hours'].append(linetokens[0])
                todayData['calories'].append(linetokens[1])
                todayData['caloriesBMR'].append(linetokens[2])
                todayData['steps'].append(linetokens[3])
                todayData['distance'].append(linetokens[4])
                todayData['floors'].append(linetokens[5])
                todayData['elevation'].append(linetokens[6])
                todayData['minutesSedentary'] += int(linetokens[7])
                todayData['minutesLightlyActive'] += int(linetokens[8])
                todayData['minutesFairlyActive'] += int(linetokens[9])
                todayData['minutesVeryActive'] += int(linetokens[10])
            counter = counter+1
    return todayData


# user login, init version create by Devi. I removed flask_login.
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        #print('User Found')
        return render_template('/index.html', data=session['user'].name)
    form = LoginForm()
    jsonPayload = None
    if form.validate_on_submit():
        jsonPayload = {
            'username': form.username.data,
            'password': form.password.data
        }
        result = requests.post(
            'http://0.0.0.0:5000/auth/login', json=jsonPayload)

        result = result.json()
        if result['status'] != 'fail':
            user = Session_User(
                form.username.data, result['auth_token'], result['user']['user_id'])

            session['user'] = user
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('web.mydashboard')
            return redirect(next_page)
        else:
            flash('Invalid username or password')
            return redirect(url_for('web.login'))
    return render_template('/login.html', title='Sign In', form=form)

# user log out, init version create by Devi. I removed flask_login.


@bp.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('web.index'))

# user register, called the API.


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session:
        return redirect(url_for('web.mydashboard'))
    form = RegistrationForm()
    jsonPayload = None
    if form.validate_on_submit():

        jsonPayload = {
            'username': form.username.data,
            'email': form.email.data,
            'password': form.password.data,
            'phone': form.phone.data,
            'name': form.fname.data,
            'lname': form.lname.data,
            'gender': form.gender.data,
            'address': form.address.data,
            'city': form.city.data,
            'zipcode': form.zipcode.data,
            'state': form.state.data
        }
        # print(jsonPayload)
        result = requests.post(
            'http://0.0.0.0:5000/auth/register', json=jsonPayload)

        result = result.json()
        if result['status'] == 'success':
            flash(
                'Congratulations, you registered an account! Please verify your email first.')
            return redirect(url_for('web.login'))
        flash('The username or email have already registered.')
    return render_template('/register.html', title='Register', form=form)

# password reset with token


@bp.route("/reset_password_request", methods=['GET', 'POST'])
def reset_request():
    # if current_user.is_authenticated:
    # return redirect(url_for('index'))
    form = RequestResetForm()
    if form.validate_on_submit():
        jsonPayload = {
            'email': form.email.data,
        }
        result = requests.post(
            'http://0.0.0.0:5000/auth/reset_password_request', json=jsonPayload)
        result = result.json()
        if result['status'] == 'success':
            flash('Email has been sent to reset your password', '_info_')
            return redirect(url_for('web.login'))

        flash('We did not find that email address in our records. Please check and re-enter it or register for a new account.', '_info_')
    return render_template('/reset_request.html', title='Reset Password', form=form)

# show today's data on the dashboard


@bp.route('/mydashboard', methods=['GET'])
def mydashboard():
    if 'user' in session:
        today = date.today()
        todayData = mongo.db.user_stats.find_one(
            {'user_id': session['user'].uid, 'date': today.strftime("%Y-%m-%d")})
        # connect to s3 bucket

        DateString = today.strftime("%Y-%m-%d")
        DateString = str(DateString)
        print(DateString)
        Summary = retrieveFitbitSummary(DateString)
        # Sleep data array consisting of [Awake,Light,Deep,Rem] sleep
        Sleep = retrieveSleepData(DateString)

        # read hourly data file. each line of data is in 15 minute increments
        todayData = retrieveHourlyData(DateString)

        return render_template('/mydashboard.html', Summary=Summary, todayData=todayData, Sleep=Sleep)
    else:
        return redirect(url_for('web.login'))

# show profile


@bp.route('/myprofile', methods=['GET'])
def myprofile():
    if 'user' in session:
        userProfile = User.get_by_id(session['user'].uid)
        return render_template('/myprofile.html', user=userProfile)
    else:
        return redirect(url_for('web.login'))

# update profile


@bp.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user' in session:
        form = updateProfileForm()
        if form.validate_on_submit():
            Database.update_one(collection="users", query=[{'user_id': session['user'].uid},
                                                           {"$set": {"uname": form.username.data, "fname": form.fname.data, "lname": form.lname.data, "bio": form.bio.data, "phone": form.phone.data, "address": form.address.data, "city": form.city.data, "zipcode": form.zipcode.data, "state": form.state.data}}])
            flash('Your profile has been updated.')
            # change session username to newone once update the database
            session['user'].name = form.username.data
            # print(session['user'].name)
            # return to myprofile page
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

# change password


@bp.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' in session:
        form = changePasswordForm()
        if form.validate_on_submit():
            # update the password
            Database.update_one(collection="users", query=[{'uname': session['user'].name}, {
                                "$set": {"password": form.password.data}}])
            flash('Your password has been changed.')
            # back to profile page
            userProfile = User.get_by_username(session['user'].name)
            return render_template('/myprofile.html', user=userProfile)
        return render_template('/changePassword.html', title='Change Password', form=form)
    else:
        return redirect(url_for('web.index'))

# request a pic for the profile


@bp.route('/request_file/<filename>')
def request_file(filename):
    if 'user' in session:
        # if the filename is default. send the default.jpg
        if filename == 'default':
            # need to upload a pic 'default' to the database when depoly the system to AWS.
            return mongo.send_file('default')
        else:
            return mongo.send_file(filename)
    # if user isn't exist.
    else:
        return redirect(url_for('web.index'))

# upload a pic to the database


@bp.route('/uploader', methods=['GET', 'POST'])
def upload_file():
    if 'user' in session:
        if 'profile_pic' in request.files:
            # make sure that the filename is unique
            profile_pic = request.files['profile_pic']
            files = mongo.db.fs.files.find(
                {'filename': profile_pic.filename}).count()
            # print(files)
            if files == 0:  # if files is not empty
                # upload the pic
                mongo.save_file(profile_pic.filename, profile_pic)
                # get previous filename
                user = User.get_by_username(session['user'].name)
                previousFilename = user.profile_pic
                # update the profile
                query = {'uname': session['user'].name}
                updates = {"$set": {"profile_pic": profile_pic.filename}}
                mongo.db.users.update_one(query, updates)

                # delete the old file if it isn't default
                if previousFilename != 'default':
                    # get fs.files _id for previousfile #find_one doesn't work.
                    fileobject = mongo.db.fs.files.find(
                        {'filename': previousFilename})
                    # print(fileobject[0]['_id'])
                    # delete the old file chunks from fs.chunks
                    mongo.db.fs.chunks.remove(
                        {'files_id': fileobject[0]['_id']})
                    # delete the old file record from fs.files
                    mongo.db.fs.files.remove({'_id': fileobject[0]['_id']})
            else:
                flash('The filename has been used. Please choice a different file name.')

            return redirect(url_for('web.myprofile'))
    else:
        return redirect(url_for('web.index'))

