from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "foxmccloud"

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    if 'loggedIn' not in session:
        session['loggedIn'] = False
    else:
        session['loggedIn'] = True
    return render_template('index.html')

@app.route('/register', methods=["POST"])
def register():
    # validation check for First Name
    if len(request.form['first_name']) < 1:
        flash('First Name is required', 'first_name')
    elif not request.form['first_name'].isalpha():
        flash("Only use alphabets in first name")

    # validation check for Last Name
    if len(request.form['last_name']) < 1:
        flash('Last Name is required', 'last_name')
    elif not request.form['last_name'].isalpha():
        flash("Only use alphabets in last name")

    # validation check for email
    if len(request.form['email']) < 1:
        flash('Email is required', 'email')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash('Email is Invalid', 'email')
    else:
        query = 'SELECT * FROM users WHERE email = %(email)s'
        data = {'email': request.form['email'] }
        mysql = connectToMySQL('walldb')
        result = mysql.query_db(query, data)

    # validation for password
    if len(request.form['password']) < 1:
        flash('Password is required', 'password')
    elif len(request.form['password']) < 8:
        flash('Password must be at least 8 characters', 'password')
    elif not re.search('[0-9]', request.form['password']):
        flash('Password must have at least one number', 'password')
    elif not re.search('[A-Z]', request.form['password']):
        flash('Password must have at least one capital letter', 'password')
    elif request.form['password'] != request.form['confirm_password']:
        flash('Passwords did not match', 'confirm_password')


    if '_flashes' in session.keys():
        # pass form data to sessions
        session['first_name'], session['last_name'], session['email']= request.form['first_name'], request.form['last_name'], request.form['email']
        return redirect('/')

    else: # No validation error so insert data to the database
        # create an hash password
        pw_hash = bcrypt.generate_password_hash(request.form['password'])

        # get data from the form
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'].strip().lower() ,
            'password': pw_hash
        }

        # connect to my Database and run insert query
        mysql = connectToMySQL('walldb')
        query = 'INSERT INTO users (first_name, last_name, email, password,created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW() )'

        session['user_id'] = mysql.query_db(query, data)
        return redirect('/home')

@app.route('/login', methods=['POST'])
def login():
    # check if this is a POST request
    if request.method != 'POST':
        session.clear()
        return redirect('/')

    # get the form data
    data = { 'email': request.form['email'].strip().lower() }
    query = 'SELECT * FROM users WHERE email = %(email)s'
    mysql = connectToMySQL('walldb')
    result = mysql.query_db(query, data)

    if len(result) > 0:
        user = result[0]
        if bcrypt.check_password_hash(user['password'], request.form['password']):
            session['user_id'] = user['id']
            session['loggedIn'] = True
            return redirect('/home')

    flash(' Your Log-In information was incorrect', 'login')
    return redirect('/')




if __name__=="__main__":
    app.run(debug=True)
