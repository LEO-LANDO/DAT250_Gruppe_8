from pickle import FALSE
from flask import Flask, session , g 
from flask_session import Session
from config import Config
from flask_bootstrap import Bootstrap
#from flask_login import LoginManager
import sqlite3
import os

# |NB!|FLASK LOGIN| ---------------------------------------------------------------------------------------
from flask_login import LoginManager
import sqlite3
import os
from datetime import timedelta


# -------------------------------------------------------------------------------------------------------------
# create and configure app
app = Flask(__name__)
Bootstrap(app)
app.config.from_object(Config)


# |NB!|FLASK LOGIN| ---------------------------------------------------------------------------------------
# TODO: Handle login management better, maybe with flask_login?
#login = LoginManager(app)
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=24)
app.config['REMEMBER_COOKIE_NAME'] = 'remember'
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

login_manager = LoginManager(app)
login_manager.login_view = '/index'

# --------------------------------------------------------------------------------------------------------------



# TODO: Handle login management better, maybe with flask_login?
#login = LoginManager(app)

# get an instance of the db
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

# initialize db for the first time
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# perform generic query, not very secure yet
def query_db(query, one=False):
    db = get_db()
    cursor = db.execute(query)
    rv = cursor.fetchall()
    cursor.close()
    db.commit()
    return (rv[0] if rv else None) if one else rv



# TODO: Add more specific queries to simplify code

def check_user(username):
    conn = get_db()
    with conn:
        c = conn.cursor()
        check = c.execute('SELECT * FROM Users WHERE username=?;', (username,)).fetchall()
        try:
            (type(check[0]))
        except IndexError:
            return False 
        return True


def login_db(login_un,login_pass):      #Logs in user by checking user input against information on database
    conn = get_db()
    with conn:
        c = conn.cursor()
        test = "SELECT * FROM Users WHERE username=?;"
        check = c.execute(test, (login_un,))
        user = check.fetchall()
        try:
            (type(user[0]))
        except IndexError:
            return False 
        if user[0][4] != login_pass:
            return False
        if user == None:
            return False
        return True
        

def register_query(Reg_info):       #registers new users in database
    conn = get_db()
    with conn:
        c = conn.cursor()
        check_username = c.execute('SELECT * FROM Users WHERE username=?;',(Reg_info[0],)).fetchall()
        if len(check_username) != 0:
            return False
        test = "INSERT INTO Users (username, first_name, last_name, password) VALUES(?,?,?,?);"
        c.execute(test, (Reg_info[0],Reg_info[1],Reg_info[2],Reg_info[3]))
        return True

def get_user(username):     #return information about user
    conn = get_db()
    with conn:
        c = conn.cursor()
        checkusername = c.execute('SELECT * FROM Users WHERE username=?;',(username,)).fetchall()
    if len(checkusername) == 0:
        return None
    else:
        return checkusername[0]


def post_query(id, content, filename, post_time):
    conn = get_db()
    with conn:
        c=conn.cursor()
        c.execute('INSERT INTO Posts (u_id, content, image, creation_time) VALUES(?, ?, ?, ?);', (id, content, filename, post_time))

def comment_query(p_id, user, comment, date):
    conn = get_db()
    with conn:
        c = conn.cursor()
        c.execute('INSERT INTO Comments (p_id, u_id, comment, creation_time) VALUES(?, ?, ?, ?);',(p_id, user, comment, date))



def update_profile(education,employment,music, movie, nationality, birthday, username):
    conn = get_db()
    with conn:
        c = conn.cursor()
        c.execute('UPDATE Users SET education=?, employment=?, music=?, movie=?, nationality=?, birthday=? WHERE username=? ;',
        (education,employment,music, movie, nationality, birthday, username))

def comment_query(p_id, user_id, comment, date):
    conn = get_db()
    with conn:
        c=conn.cursor()
        c.execute('INSERT INTO Comments (p_id, u_id, comment, creation_time) VALUES(?, ?, ?, ?);', (p_id, user_id, comment, date))

def friend_query(user,friend):
    conn = get_db()
    with conn:
        c = conn.cursor()
        c.execute('INSERT INTO Friends (u_id, f_id) VALUES(?, ?);',(user, friend))



# automatically called when application is closed, and closes db connection
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# initialize db if it does not exist
if not os.path.exists(app.config['DATABASE']):
    init_db()

if not os.path.exists(app.config['UPLOAD_PATH']):
    os.mkdir(app.config['UPLOAD_PATH'])

from app import routes