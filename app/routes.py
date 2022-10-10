from atexit import register
import http
from flask import render_template, flash, redirect, url_for, Markup, request, session, make_response
from app import app, comment_query, query_db, login_db, register_query, get_user, update_profile, post_query, check_user, friend_query
from app.forms import IndexForm, PostForm, FriendsForm, ProfileForm, CommentsForm
# ---------------------------------------------------------------------------------------------------------
from datetime import datetime
import os
# ---------------------------------------------------------------------------------------------------------

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from app import login_manager
# ---------------------------------------------------------------------------------------------------------

# this file contains all the different routes, and the logic for communicating with the database
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower in app.config["ALLOWED_EXTENTIONS"]

# |NB!|FLASK LOGIN| ---------------------------------------------------------------------------------------

class User(UserMixin):
    def __init__(self, username, password, id=0):
        self.__id = id
        self.__username = username
        self.__password = password
    
    def get_id(self):
        return self.__username
    def get_password(self):
        return self.__password
    def get_name_User_query(username):
        query = query_db('SELECT * FROM Users WHERE username="{}";'.format(username), one=True)
        user = User(username=query['username'], password=query['password'], id=query['id'])
        return user

@login_manager.user_loader
def load_user(username):
    return User.get_name_User_query(username)


# -- |APP| ---------------------------------------------------------------------------------------
# home page/login/registration
@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    form = IndexForm()

    if current_user.get_id() != None:
        session["username"] = current_user.get_id() 
        return redirect('stream')

    if form.login.is_submitted() and form.login.submit.data:
        user_find = query_db('SELECT * FROM Users WHERE username="{}";'.format(form.login.username.data), one=True)
        if form.login.validate_on_submit():
            if check_user(form.login.username.data) == True:
                # -- |HASHING|
                if check_password_hash(user_find['password'], form.login.password.data) == True:
                    session["username"] = form.login.username.data
                    user = load_user(form.login.username.data)
                    login_user(user, remember=True)
                    flash(f"Welcome {form.login.username.data}!")
                    return redirect(url_for('stream'))
                else:
                    flash('Sorry, wrong username or password!')
            else:
                flash('Sorry, wrong username or password!')

    elif form.register.is_submitted() and form.register.submit.data and form.register.validate_on_submit():
        # -- |HASHING| 
        hashed_password = generate_password_hash(form.register.password.data, method='sha256')

        registration_info = (form.register.username.data, form.register.first_name.data, 
        form.register.last_name.data, hashed_password)
        if register_query(registration_info) == True:
            session["username"] = form.register.username.data
            flash(f"Welcome {form.register.username.data}")
            return redirect(url_for('stream'))
        else:
            flash("Username already taken!")
    
    # -- |COOKIES|
    res = make_response(render_template('index.html', title='Welcome', form=form))
    count = int(request.cookies.get('visit-index-count', 0))
    count += 1
    res.set_cookie('visit-index-count', str(count),httponly=True, samesite='Lax')
    return res


# content stream page

app.config["ALLOWED_IMAGE_EXTENSION"] = ["png", "jpg", "jpeg", "gif"]
@app.route('/stream', methods=['GET', 'POST'])
@login_required
def stream():
    # -- |SESSION| 
    session["username"] = current_user.get_id()
    username = session["username"]
    
    if session["username"] == None:
        return redirect("/index")
    if username != session.get("username"):
        flash("Access denied: Not logged in!")
        return redirect(url_for('index'))

    form = PostForm()
    user = query_db('SELECT * FROM Users WHERE username="{}";'.format(username), one=True)
    if form.is_submitted():
        if form.image.data:

            if form.image.data.filename == "":
                flash("Image needs name")
                return redirect(url_for('stream', username=username))
            
            if not "." in form.image.data.filename:
                flash("File type needed")
                return redirect(url_for('stream', username=username))
            else:
                filename = secure_filename(form.image.data.filename)

            ext = filename.rsplit(".", 1)[1]

            if ext.lower() not in app.config["ALLOWED_IMAGE_EXTENSION"]:
                flash("File type is not valid")
                return redirect(url_for('stream', username=username))

            path = os.path.join(
                app.config['UPLOAD_PATH'], filename)
            form.image.data.save(path)
        post_query(user['id'], form.content.data, filename, datetime.now())
        return redirect(url_for('stream'))
    posts = query_db('SELECT p.*, u.*, (SELECT COUNT(*) FROM Comments WHERE p_id=p.id) AS cc FROM Posts AS p JOIN Users AS u ON u.id=p.u_id WHERE p.u_id IN (SELECT u_id FROM Friends WHERE f_id={0}) OR p.u_id IN (SELECT f_id FROM Friends WHERE u_id={0}) OR p.u_id={0} ORDER BY p.creation_time DESC;'.format(user['id']))
    
    # -- |COOKIES|
    res = make_response(render_template('stream.html', title='Stream', username=username, form=form, posts=posts))
    count = int(request.cookies.get('visit-stream-count', 0))
    count += 1
    res.set_cookie('visit-stream-count', str(count))
    return res


# comment page for a given post and user.
@app.route('/comments/<int:p_id>', methods=['GET', 'POST'])
@login_required
def comments(username, p_id):

    session["username"] = current_user.get_id()
    username = session["username"]

    if session["username"] == None:
        return redirect("/index")
    if username != session.get("username"):
        flash("Access denied: Not logged in!")
        return redirect(url_for('index'))

    form = CommentsForm()
    if form.is_submitted():
        user = query_db('SELECT * FROM Users WHERE username="?";'.format(username), one=True)
        comment_query(p_id, user['id'], form.comment.data, datetime.now())

    post = query_db('SELECT * FROM Posts WHERE id={};'.format(p_id), one=True)
    all_comments = query_db('SELECT DISTINCT * FROM Comments AS c JOIN Users AS u ON c.u_id=u.id WHERE c.p_id={} ORDER BY c.creation_time DESC;'.format(p_id))
    return render_template('comments.html', title='Comments', username=username, form=form, post=post, comments=all_comments)
    

# page for seeing and adding friends
@app.route('/friends', methods=['GET', 'POST'])
@login_required
def friends():

    session["username"] = current_user.get_id()
    username = session["username"]

    if session["username"] == None:
        return redirect("/index")
    if username != session.get("username"):
        flash("Access denied: Not logged in!")
        return redirect(url_for('index'))
    
    form = FriendsForm()
    user = query_db('SELECT * FROM Users WHERE username="{}";'.format(username), one=True)
    if form.is_submitted():
        friend = query_db('SELECT * FROM Users WHERE username="{}";'.format(form.username.data), one=True)
        if friend is None:
            flash('User does not exist')
        else:
            friend_query(user['id'], friend['id'])
    
    all_friends = query_db('SELECT * FROM Friends AS f JOIN Users as u ON f.f_id=u.id WHERE f.u_id={} AND f.f_id!={} ;'.format(user['id'], user['id']))
    
    # -- |COOKIES|
    res = make_response(render_template('friends.html', title='Friends', username=username, friends=all_friends, form=form))
    count = int(request.cookies.get('visit-firend-count', 0))
    count += 1
    res.set_cookie('visit-firend-count', str(count))
    return res


# see and edit detailed profile information of a user
@app.route('/profile/<username>', methods=['GET', 'POST'])
@login_required
def profile(username):
    form = ProfileForm()
    if form.is_submitted():
        update_profile(form.education.data, form.employment.data, form.music.data, form.movie.data, form.nationality.data, form.birthday.data, username)
        return redirect(url_for('profile', username=username))
    user = get_user(username)
    if session["username"] == None:
        flash("Access denied: You're not logged in!")
        return redirect("/index")
    elif session["username"] != username:
        return render_template('profile_loggedin.html', title='profile', username=username, user=user, form=form)
    if user[5] != None:
        form.education.data = user[5]
    if user[6] != None:
        form.employment.data = user[6]
    if user[7] != None:
        form.music.data = user[7]
    if user[8] != None:
        form.movie.data = user[8]
    if user[9] != None:
        form.nationality.data = user[9]
    if user[10] != None:
        if user[10] != "Unknown":
            form.birthday.data = datetime.strptime(user[10], "%Y-%m-%d")
    
    # -- |COOKIES|
    res = make_response(render_template('profile.html', title='profile', username=username, user=user, form=form))
    count = int(request.cookies.get('visit-profile-count', 0))
    count += 1
    res.set_cookie('visit-profile-count', str(count))
    return res

# Header
@app.after_request
def add_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self' https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com https://code.jquery.com; style-src 'self' https://maxcdn.bootstrapcdn.com/ https://stackpath.bootstrapcdn.com; img-src 'self' https: data:; font-src 'self' https://maxcdn.bootstrapcdn.com"
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'NOSNIFF'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.route('/logout')
def logout():
    
    session["username"] = None
    logout_user()

    flash("You've been successfully logged out")
    return redirect("/index")

@app.route('/set/')
def set():
    session['key'] = 'value'
    return 'ok'

@app.route('/get/')
def get():
    return session.get('key', 'not set')


