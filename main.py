from ast import Not
from cgitb import reset
from dataclasses import dataclass
#from crypt import methods
#from crypt import methods
#from crypt import methods
import email
from pickle import TRUE
##from crypt import methods
##from crypt import methods
from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
import MySQLdb.cursors
import re
import html
import binascii
import os
import hashlib
import ConfigurationModule as PasswordManager
import ssl
from OpenSSL import SSL


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('ssl/certificate.pem',  'ssl/key.pem')
# context = SSL.Context(SSL.TLSv1_2_METHOD)
# context.use_certificate("ssl/certificate.pem")
# context.use_privatekey("ssl/key.pem")

app = Flask(__name__)
mail = Mail(app)


# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'KostyaWasHere'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '3375'
app.config['MYSQL_DB'] = 'pythonlogin'

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'fakeemailcs22@gmail.com'
app.config['MAIL_PASSWORD'] = 'qocvcvgqkadekifo'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


# Intialize MySQL
mysql = MySQL(app)


def get_hashed_password(password, salt):
    hash = hashlib.pbkdf2_hmac( 'sha1', password.encode(), salt.encode(), 100000)
    password = binascii.hexlify(hash)
    return password

password_conf = PasswordManager.read_conf()

# http://localhost:5000 - the following will be our login page, which will use both GET and POST requests
@app.route('/', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        #The attecker cannot attack
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        #The attacker can attack
        #cursor.execute("SELECT * FROM accounts WHERE username = '%s'" % username)

        # Fetch one record and return result
        account = cursor.fetchone()

        # check if account exist in database
        if account:
            if cursor.rowcount!=1:
                session['cursor'] = True
            else:
                session['cursor'] = False
                login_attempts = account['login_attempts']

            salt_byte = account['salt'].encode()  
            hash = hashlib.pbkdf2_hmac('sha1', password.encode(), salt_byte, 100000)  
            password = binascii.hexlify(hash) 

            #The attecker cannot attack
            cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s' ,( username, password,))
            #The attacker can attack


            account = cursor.fetchone()
        else:
            # user name doesn't exist
            msg = "user name doesn't exist"
            return render_template('index.html', msg=msg)

        # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['email'] = account['email']
            # Redirect to home page
            ##return 'Logged in successfully!'
            return render_template('addCostumer.html/',userName=username, msg=msg)
        elif session['cursor'] == True and cursor.rowcount!=1:
            #To show the attack
            return render_template('index.html', msg='Incorrect username/password!')
        else:
            if(int(login_attempts) >= password_conf["loginAttempts"]):
                msg = 'you tried to login too many times, contact us to reset your account'
                return render_template('index.html', msg=msg)

            # Account doesnt exist or username/password incorrect
            cursor.execute('UPDATE accounts SET login_attempts = %s WHERE username = %s',
                     (int(login_attempts)+1, username))
            mysql.connection.commit()
            msg = 'Incorrect username/password!'
    # Show the login form with message (if any)
    return render_template('index.html', msg=msg)


    # http://localhost:5000/python/logout - this will be the logout page
@app.route('/pythonlogin/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))

@app.route('/pythonlogin/forgetPassword',methods=['GET', 'POST'])
def forgetPassword():
    msg = ''
    if request.method == 'POST' and 'email' in request.form:
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
        account = cursor.fetchone()

        if account:

            hash = hashlib.pbkdf2_hmac(
                'sha1', email.encode(), account['salt'].encode(), 10000)  
            reset_code = binascii.hexlify(hash)  
            cursor.execute(
                'UPDATE accounts SET restart_password_code = %s WHERE email = %s', (reset_code, email,))
            mysql.connection.commit()

            email_info = Message(
                'Password Reset', sender='kostyaul@gmail.com', recipients=[email])
            email_info.body = 'Copy this code to reset your password\n' + \
                reset_code.decode('utf-8')
            mail.send(email_info)

            return render_template('reset_password.html/',email=email)

        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        else:
            msg = 'email does not'
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'

    return render_template('forgetPassword.html',msg=msg)

@app.route('/pythonlogin/reset_password/<string:email>',methods=['GET','POST'])
def reset_password(email):
    if request.method == 'POST' and 'reset_password' in request.form:
        reset_code = request.form['reset_password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'SELECT * FROM accounts WHERE email = %s AND restart_password_code = %s', (email, reset_code))
        account = cursor.fetchone()

        if account: 
            return render_template('change_password.html/',email=email)
    return render_template('reset_password.html/',email = email,msg="wrong code")

@app.route('/pythonlogin/change_password/<string:email>',methods=['GET','POST'])
def change_password(email):
    salt = os.urandom(16)  
    salt_byte = binascii.hexlify(salt)
    if request.method == 'POST' and 'password' in request.form:
        password = request.form['password']
        
        if(len(password) < password_conf["passwordLength"]):
            msg = 'Password too short'
            return render_template('change_password.html/',email=email, msg=msg)
        if(not PasswordManager.check_password(password)):
            msg = 'weak password'
            return render_template('change_password.html/',email=email, msg=msg)

        hash = hashlib.pbkdf2_hmac('sha1', password.encode(), salt_byte, 100000)  
        password = binascii.hexlify(hash)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
        account = cursor.fetchone()
        # If account exists show error and validation checks
        if account:
            salt_password_now = account["salt"];
            password_now = account["password"];
            count_changes = account["count_changes"];

        number= int(count_changes)%3;
        number_s= str(int(count_changes)+1)
        cursor.execute('UPDATE accounts SET history_password_'+str(number)+' = %s WHERE email = %s', (password_now, email,))
        cursor.execute('UPDATE accounts SET history_salt_'+str(number)+' = %s WHERE email = %s', (salt_password_now, email,))
        cursor.execute('UPDATE accounts SET count_changes=%s WHERE email = %s', (number_s, email,))
        cursor.execute('UPDATE accounts SET password = %s WHERE email = %s', (password, email,))
        cursor.execute('UPDATE accounts SET salt = %s WHERE email = %s', (salt_byte, email,))

        mysql.connection.commit()

        if session['loggedin'] is not None:
            if session['loggedin'] == True:
                return render_template('addCostumer.html')

    return render_template('index.html')

   # http://localhost:5000/pythinlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    salt = os.urandom(16)  
    salt_byte = binascii.hexlify(salt)
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access

        password = request.form['password']
        
        if(len(password) < password_conf["passwordLength"]):
            msg = 'Password too short'
            return render_template('register.html', msg=msg)
        if(not PasswordManager.check_password(password)):
            msg = 'weak password'
            return render_template('register.html', msg=msg)

        username = request.form['username']
        email = request.form['email']  
        hash = hashlib.pbkdf2_hmac('sha1', password.encode(), salt_byte, 100000)  
        login_attempts = '0'  
        password = binascii.hexlify(hash)

         # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        #The attacker cannot attack
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        #The attacker can attack
        #cursor.execute("SELECT * FROM accounts WHERE username ='%s' " % username)
        #cursor.execute("SELECT * FROM accounts WHERE username =" + username)

        account = cursor.fetchone()
        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Name must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            count_changes=0;
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            cursor.execute('INSERT INTO accounts (username, password, email, salt, login_attempts,count_changes) VALUES (%s, %s, %s, %s, %s,%s)',
                           (username, password, email, salt_byte, login_attempts,count_changes))

            #cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s ,%s)', (username, password, email,salt))
            mysql.connection.commit()
            msg = 'You have successfully registered!'

    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)

@app.route('/pythonlogin/addCostumer', methods=['GET', 'POST'])
def addCostumer():
    msg=''
    if request.method == 'POST' and 'id' in request.form and 'costumername' in request.form and 'email' in request.form:
        #The attacker can attack
        #email = request.form['email']
        #name = request.form['costumername']

        #The ID is protected as it is only digits
        id = request.form['id']

        #The attecker cannot attack
        email = html.escape(request.form['email'])
        name= html.escape(request.form['costumername'])

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM costumers WHERE costumerId = %s', (id,))
        account = cursor.fetchone()

        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        #can also help against the attack by preventing the user from entering special charactes but only characters
        elif not re.match(r'[A-Za-z]+', name):
           msg = 'Name must contain only characters!'
        elif not re.match(r'[0-9]+', id) or not len(id)==9:
            msg = 'Invalid Id!'
        elif not id or not name or not email:
            msg = 'Please fill out the form!'
        else:
            cursor.execute('INSERT INTO costumers (costumerId, costumerEmail, costumerName, registerBy) VALUES (%s, %s, %s, %s)',
                           (id,email,name,session['username']))

            #cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s ,%s)', (username, password, email,salt))
            mysql.connection.commit()
            msg = name+ ' have been added to the system'
    return render_template('addCostumer.html',msg=msg)

@app.route('/pythonlogin/confirmationPasswordChange',methods=['GET','POST'])
def confirmationPasswordChange():
    if request.method == 'POST':
        return render_template('change_password.html',email = session['email'])
    return render_template('confirmationPasswordChange.html')

@app.route('/pythonlogin/showCostumer', methods=['GET', 'POST'])
def showCostumer():
    msg=''
    if request.method == 'POST' and 'id' in request.form:
        id = request.form['id']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        cursor.execute('SELECT * FROM costumers WHERE costumerId = %s', (id,))
        #cursor.execute("SELECT * FROM costumers WHERE costumerId = '%s'" % id)

        account = cursor.fetchone()

        if account:
            session['costumerId'] = id
            data = ((account['costumerName'],account['costumerId'],account['costumerEmail'],account['registerBy']))
            return render_template('infoCostumer.html',data=data)
        elif not re.match(r'[0-9]+', id) or not len(id)==9:
            msg = 'Invalid Id!'
        elif not id:
            msg = 'Please fill out the form!'
        else:
            msg = 'not found'

    return render_template('showCostumer.html',msg=msg)

@app.route('/pythonlogin/infoCostumer',methods=['GET','POST'])
def infoCostumer():
    return render_template('infoCostumer.html')

if __name__ == "__main__":
   app.run(ssl_context=context)