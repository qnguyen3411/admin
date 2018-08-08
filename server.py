from flask import Flask, render_template, redirect, request, session, flash
from mySQLconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import string
import re
app = Flask(__name__)
app.secret_key = "Secret"

bcrypt = Bcrypt(app)
mysql = connectToMySQL('advancedlog')

EMAIL_REGEX =re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PW_REGEX1=re.compile(r'^.{8,15}$')
PW_REGEX2=re.compile(r'^.*[0-9].*$')
PW_REGEX3=re.compile(r'^.*[A-Z].*$')

@app.route('/')
def index():
    if len(session) == 0:
        session['id'] = False
        session['userinfo'] = False
        session['mails'] = False
        session['friends'] = False
        
    if session['id']:
        if session['userinfo']['user_level'] == 9:
            return redirect('/admin')
        else:
            return redirect('/user')
    return render_template('index.html', logID=session['id'], info=session['userinfo'])

@app.route('/reg_validate', methods=['POST'])
def regValidate():
    validInput = True
    #validate data
    if len(request.form['first_name']) < 2 or not request.form['first_name'].isalpha():
        flash(u"badfirstname","badFirstName")
        validInput = False
    if len(request.form['last_name']) < 2 or not request.form['last_name'].isalpha():
        flash(u"badlastname","badLastName")
        validInput = False
    if not re.match(EMAIL_REGEX, request.form['email']):
        flash(u"bademail","badEmail")
        validInput = False
    if not PW_REGEX1.match(request.form['password']) or not PW_REGEX2.match(request.form['password']) or not PW_REGEX3.match(request.form['password']):
        flash(u"badpw","badPW")
        validInput = False
    if request.form['pwconfirm'] != request.form['password']:
        flash(u"badconfirm","badConfirm")
        validInput = False
    #see if email is already in database
    if validInput:

        data = {'email' : request.form['email']}
        findMatchQuery = "SELECT * FROM users WHERE email = %(email)s;"
        if mysql.query_db(findMatchQuery, data):
            flash(u"dupeEmail","dupeEmail")
    #if valid input, hash pw and insert user into database
        else:
            pw_hash = bcrypt.generate_password_hash(request.form['password'])
            data = { "first_name" : request.form['first_name'],
                    "last_name" : request.form['last_name'],
                    "email"     : request.form['email'],
                    "user_level" : 1,
                    "password_hash": pw_hash
            }
            insertQuery = "INSERT INTO users (first_name, last_name, email, password, user_level, created_at, updated_at) VALUES(%(first_name)s, %(last_name)s, %(email)s, %(password_hash)s, %(user_level)s, NOW(), NOW());"
            userid = mysql.query_db(insertQuery,data)
            session['id'] = userid
            session['userinfo']['first_name'] = data['first_name']
            session['userinfo']['last_name'] = data['last_name']
            session['userinfo']['email'] = data['email']
            session['userinfo']['user_level'] = data['user_level']
            
            
    return redirect('/')

@app.route('/log_validate', methods=['POST'])
def logValidate():
    print(request.form)
    data = {'email' : request.form['email']}
    findMatchQuery = "SELECT id, first_name, last_name ,email, password, user_level FROM users WHERE email = %(email)s;"
    user = mysql.query_db(findMatchQuery, data)
    
    if user and bcrypt.check_password_hash(user[0]['password'], request.form['password']):
        flash(u"","logSuccess")
        print(user)
        session['id'] = user[0]['id']
        session['userinfo']={ 'first_name': user[0]['first_name'],
                            'last_name': user[0]['last_name'],
                            'email': user[0]['email'], 
                            'user_level': user[0]['user_level']
                            }
        print(session)
        return redirect('/')
    else:
        flash(u"Wrong email/password combination","badLogin")
        return redirect('/')

@app.route('/admin')
def renderAdmin():
    if session['id']:
        if session['userinfo']['user_level'] == 9:
            userList = mysql.query_db("SELECT id, CONCAT(first_name,' ', last_name) AS name, email, user_level FROM users; ")
            return render_template('admin.html', userList=userList)
        else:
            return redirect('/user')
    return redirect('/')

@app.route('/remove_user', methods=['POST'])
def removeUser():
    print(request.form)
    deleteQuery = "DELETE FROM users WHERE id = %(id)s"
    mysql.query_db(deleteQuery, request.form)
    return redirect('/admin')

@app.route('/change_access', methods=['POST'])
def changeAccess():
    print(request.form['id'])
    if request.form['user_level'] == '1':
        updated_user_level = 9
    else:
        updated_user_level = 1
    data = {
        'id' : request.form['id'],
        'user_level': updated_user_level
    } 
    updateQuery = "UPDATE users SET user_level = %(user_level)s WHERE id = %(id)s"
    mysql.query_db(updateQuery, data)

    return redirect('/admin')

@app.route('/user')
def renderUser():
    if session['id']:
        return render_template('user.html')
    return redirect('/')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/')
if __name__ == '__main__':
	app.run(debug=True)
