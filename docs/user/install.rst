.. _install:

Installation of FitBackend
========================

.. image:: https://farm5.staticflickr.com/4230/35550376215_da1bf77a8c_k_d.jpg


This part of the documentation covers the installation of Backend, AdminUI and Customer Dashboard UI.
The first step to using any software package is getting it properly installed.



This repo contains API logic, End-to-end ML logic and admin portal UI.
## Dependency |FOSSA Status|

1. Redis
2. MongoDB
3. Python 3.6+
4. Pip ### Optional
5. Docker
6. Nginx

Video Instruction
-----------------

Dev Tutorial
~~~~~~~~~~~~

-  Ubuntu video: https://www.youtube.com/watch?v=zXw3ioJmmmQ
-  Mac video: https://www.youtube.com/watch?v=y0qnhue3PJE ### API
   Tutorial
-  API (Login, Register, Verify Email, Logout, User Status, User Info)
   Video: https://www.youtube.com/watch?v=LW5f2yZnJgg

Deploy Server
-------------

Python Realated Installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run the following to make user you have all softwares that are required

.. code:: console

    sudo apt update
    sudo apt install python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools

Now we will install software to create virtual python enviroment by
running the following

.. code:: console

    sudo apt install python3-venv

Now that we have installed the software. Lets create a virtual
enviroment

.. code:: console

    cd apiAdmin
    python3.6 -m venv api

Lets activate the enviroment like this (Assuming that you are inside
apiAdmin directory.

.. code:: console

    source api/bin/activate

Once you you are in virtual enviroment you will see something like this:

.. code:: console

    (api) devitripathy@macbook-pro-3 apiAdmin %
    or 
    (api) ubuntu@ip-172-31-3-80:~/apiAdmin$

Now, we need to install all python related packages. To do so run the
following:

.. code:: console

    pip install -r requirements.txt

Now there are some more dependent software we need to install before
proceeding

Redis Installation
~~~~~~~~~~~~~~~~~~

We need Redis Server running as it will act a message borker to allow
background asynchronous task. Run following:

.. code:: console

    sudo apt update
    sudo apt install redis-server

Open this file with your preferred text editor vim or nano:

.. code:: console

    sudo vi /etc/redis/redis.conf

.. code:: console

    . . .

    # If you run Redis from upstart or systemd, Redis can interact with your
    # supervision tree. Options:
    #   supervised no      - no supervision interaction
    #   supervised upstart - signal upstart by putting Redis into SIGSTOP mode
    #   supervised systemd - signal systemd by writing READY=1 to $NOTIFY_SOCKET
    #   supervised auto    - detect upstart or systemd method based on
    #                        UPSTART_JOB or NOTIFY_SOCKET environment variables
    # Note: these supervision methods only signal "process is ready."
    #       They do not enable continuous liveness pings back to your supervisor.
    supervised systemd

    . . .

make user you have supervised systemd line uncommented. if you don't see
the link add it. That’s the only change you need to make to the Redis
configuration file at this point, so save and close it when you are
finished. Then, restart the Redis service to reflect the changes you
made to the configuration file:

.. code:: console

    sudo systemctl restart redis.service

Lets see if the service is running.

.. code:: console

    sudo systemctl status redis

If it is running without any errors, this command will produce output
similar to the following:

.. code:: console

    Output
    ● redis-server.service - Advanced key-value store
       Loaded: loaded (/lib/systemd/system/redis-server.service; enabled; vendor preset: enabled)
       Active: active (running) since Wed 2018-06-27 18:48:52 UTC; 12s ago
         Docs: http://redis.io/documentation,
               man:redis-server(1)
      Process: 2421 ExecStop=/bin/kill -s TERM $MAINPID (code=exited, status=0/SUCCESS)
      Process: 2424 ExecStart=/usr/bin/redis-server /etc/redis/redis.conf (code=exited, status=0/SUCCESS)
     Main PID: 2445 (redis-server)
        Tasks: 4 (limit: 4704)
       CGroup: /system.slice/redis-server.service
               └─2445 /usr/bin/redis-server 127.0.0.1:6379

If you get any error then Google it.

Now we need to install MongoDB. ### MongoDB installation From a
terminal, issue the following command to import the MongoDB public GPG
Key from https://www.mongodb.org/static/pgp/server-4.2.asc:

.. code:: console

    wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | sudo apt-key add -

The operation should respond with an OK.

Create a list file for MongoDB. Create the list file
/etc/apt/sources.list.d/mongodb-org-4.2.list for your version of Ubuntu.

Click on the appropriate tab for your version of Ubuntu. If you are
unsure of what Ubuntu version the host is running, open a terminal or
shell on the host and execute lsb\_release -dc. The following
instruction is for Ubuntu 18.04 (Bionic). For Ubuntu 16.04 (Xenial),
click on the appropriate tab.

Create the /etc/apt/sources.list.d/mongodb-org-4.2.list file for Ubuntu
18.04 (Bionic):

.. code:: console

    echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.2.list

Issue the following command to reload the local package database:

.. code:: console

    sudo apt-get update

Now install the mongoDB

.. code:: console

    sudo apt-get install -y mongodb-org

Start the mongoDB service using

.. code:: console

    sudo systemctl start mongod

If you receive an error similar to the following when starting mongod:

Failed to start mongod.service: Unit mongod.service not found. Run the
following command first:

.. code:: console

    sudo systemctl daemon-reload

Verify that MongoDB has started successfully

.. code:: console

    sudo systemctl status mongod

To ensure that MongoDB will start following a system reboot by issuing
the following command:

.. code:: console

    sudo systemctl enable mongod

Okay now mongoDB is installed. You might face some permission issue when
runnign mongoDB with data folder. Google the solution. At this point if
you want to run a Dev mode server then skip to **Run Dev Mode** section

We now will need to create a service for our server ### Creating service
Let’s create the systemd service unit file. Creating a systemd unit file
will allow Ubuntu’s init system to automatically start uWSGI and serve
the Flask application whenever the server boots.

Create a unit file ending in .service within the /etc/systemd/system
directory to begin:

.. code:: console

    sudo vi /etc/systemd/system/api.service

Add the following to the blank file

.. code:: console


    [Unit]
    Description=Gunicorn instance to serve myproject
    After=network.target
    [Service]
    User=ubuntu
    Group=www-data
    WorkingDirectory=/home/ubuntu/apiAdmin
    Environment="PATH=/usr/bin/"
    ExecStart=/home/ubuntu/.local/bin/gunicorn --workers 3 --bind unix:myproject.sock -m 007 run:app
    [Install]
    WantedBy=multi-user.target

Things to look out for **WorkingDirectory**, **ExecStart** and
**Enviroment** variable in api.service file above.

Make use to change the **Enviroment** variable to the output of:

.. code:: console

    which python

before running which python make sure you are in your virtual
enviroment. okay now we have created a service file. Lets try to execute
our service by running the following:

.. code:: console

    sudo systemctl start api
    sudo systemctl enable myproject

Now if all went right then the service should have started. Lets check
the status of the service using:

.. code:: console

    sudo systemctl status api

you should see output like this

.. code:: console

    ● api.service - Gunicorn instance to serve myproject
       Loaded: loaded (/etc/systemd/system/api.service; enabled; vendor preset: enabled)
       Active: active (running) since Sat 2020-07-11 23:27:04 UTC; 3h 34min ago
     Main PID: 880 (gunicorn)
        Tasks: 10 (limit: 2348)
       CGroup: /system.slice/api.service
               ├─880 /usr/bin/python3 /home/ubuntu/.local/bin/gunicorn --workers 3 --bind unix:myproject.sock -m 007 run:app
               ├─953 /usr/bin/python3 /home/ubuntu/.local/bin/gunicorn --workers 3 --bind unix:myproject.sock -m 007 run:app
               ├─954 /usr/bin/python3 /home/ubuntu/.local/bin/gunicorn --workers 3 --bind unix:myproject.sock -m 007 run:app
               └─955 /usr/bin/python3 /home/ubuntu/.local/bin/gunicorn --workers 3 --bind unix:myproject.sock -m 007 run:app

    Jul 11 23:27:04 ip-172-31-3-80 systemd[1]: Started Gunicorn instance to serve myproject.
    Jul 11 23:27:07 ip-172-31-3-80 gunicorn[880]: [2020-07-11 23:27:07 +0000] [880] [INFO] Starting gunicorn 20.0.4
    Jul 11 23:27:07 ip-172-31-3-80 gunicorn[880]: [2020-07-11 23:27:07 +0000] [880] [INFO] Listening at: unix:myproject.sock (880)
    Jul 11 23:27:07 ip-172-31-3-80 gunicorn[880]: [2020-07-11 23:27:07 +0000] [880] [INFO] Using worker: sync
    Jul 11 23:27:07 ip-172-31-3-80 gunicorn[880]: [2020-07-11 23:27:07 +0000] [953] [INFO] Booting worker with pid: 953
    Jul 11 23:27:07 ip-172-31-3-80 gunicorn[880]: [2020-07-11 23:27:07 +0000] [954] [INFO] Booting worker with pid: 954
    Jul 11 23:27:07 ip-172-31-3-80 gunicorn[880]: [2020-07-11 23:27:07 +0000] [955] [INFO] Booting worker with pid: 955

If you run into any issue that is not code realted then Google it.
Otherwise contact me or raise an issue.

Our application server should now be up and running, waiting for
requests on the socket file in the project directory. Let’s configure
Nginx to pass web requests to that socket using the uwsgi protocol.

Begin by creating a new server block configuration file in Nginx’s
sites-available directory. Let’s call this api to keep in line with the
rest of the guide:

.. code:: console

    sudo vi /etc/nginx/sites-available/api

copy and paste following to the file created

.. code:: json

    server {
        listen 0.0.0.0:80;
        server_name ec2-54-214-218-104.us-west-2.compute.amazonaws.com;
        location / {
            include proxy_params;
            proxy_pass http://unix:/home/ubuntu/apiAdmin/myproject.sock;
        }
    }

Make sure **proxy\_pass** point to root dir of apiAdmin. Also, Make sure
**server\_name** is the same as your EC2 instance's Public DNS (IPv4)

Save and close the file when you’re finished.

To enable the Nginx server block configuration you’ve just created, link
the file to the sites-enabled directory:

.. code:: console

    sudo ln -s /etc/nginx/sites-available/api /etc/nginx/sites-enabled

With the file in that directory, we can test for syntax errors by
typing:

.. code:: console

    sudo nginx -t

If this returns without indicating any issues, restart the Nginx process
to read the new configuration:

.. code:: console

    sudo systemctl restart nginx

Now, the site should be visible at http://EC2 instance's Public DNS
(IPv4)

Deploying change
~~~~~~~~~~~~~~~~

When you make any changes to the API or code. To reflect the change on
the server do the following. \* First check if the code runs by running:

.. code:: console

    python run.py

If it runs fine then let's proceed: To apply changes to server run
follwing:

.. code:: console

    sudo systemctl restart api

Here some more commands that you can run to do house keeping on our app
service to stop app server service:

.. code:: console

    sudo systemctl stop api

to start app server service:

.. code:: console

    sudo systemctl start api

to check status of app server service:

.. code:: console

    sudo systemctl status api

Run Dev Mode
------------

Install all the dependencies and then create a virtual python eviroment
using anaconda or python virtual env. Install python packages using

.. code:: console

    pip install -r requirements.txt

-  Make sure Redis server and mongoDB are running. \* Then run the
   project using

   .. code:: console

       python run.py

   API and web app should now be ready to use.

Okay that concludes it. To access the database via command line do run
*mongo* and then you will need to use NoSql Command line instructions to
access database. To make the database access via Web frontednd look into
https://github.com/mrvautin/adminMongo and how to install it. Also Nginx
access logs and error log can be found at:

.. code:: console

    /var/log/nginx/access.log
    /var/log/nginx/error.log

You can also look into https://github.com/mthenw/frontail to make
access.log and error.log accessed via Web Frontend.

If you plan to use adminMongo and frontail use should look into
https://github.com/Unitech/pm2. This will make your life easy. And is
great to manage hosted services.

Okay that's about it. Contact me at tripathy.devi7@gmail.com

License
-------

|FOSSA Status|

.. |FOSSA Status| image:: https://app.fossa.com/api/projects/git%2Bgithub.com%2Fstatefarmuta%2Fapi_ml_admin.svg?type=shield
   :target: https://app.fossa.com/projects/git%2Bgithub.com%2Fstatefarmuta%2Fapi_ml_admin?ref=badge_shield
.. |FOSSA Status| image:: https://app.fossa.com/api/projects/git%2Bgithub.com%2Fstatefarmuta%2Fapi_ml_admin.svg?type=large
   :target: https://app.fossa.com/projects/git%2Bgithub.com%2Fstatefarmuta%2Fapi_ml_admin?ref=badge_large
