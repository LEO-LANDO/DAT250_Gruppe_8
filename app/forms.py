from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask import Markup
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FormField, TextAreaField, FileField
from wtforms.validators import DataRequired, InputRequired, EqualTo, Regexp
from wtforms.fields.html5 import DateField
from wtforms.csrf.core import CSRF
from app import app
from wtforms.csrf.session import SessionCSRF
from datetime import datetime, timedelta


# defines all forms in the application, these will be instantiated by the template,
# and the routes.py will read the values of the fields
# TODO: Add validation, maybe use wtforms.validators??
# TODO: There was some important security feature that wtforms provides, but I don't remember what; implement it

csrf = CSRFProtect(app)

class Meta:
    csfr = True
    csrf_class = SessionCSRF
    csrf_secret = app.config['SECRET_KEY']
    csrf_time_limit = timedelta(minutes=30)


class LoginForm(FlaskForm):
    Meta
    username = StringField('Username',[DataRequired(message="Required field")], render_kw={'placeholder': 'Username'})
    password = PasswordField('Password',[DataRequired(message="Required field")], render_kw={'placeholder': 'Password'})
    remember_me = BooleanField('Remember me') # TODO: It would be nice to have this feature implemented, probably by using cookies
    submit = SubmitField('Sign In')

class RegisterForm(FlaskForm):
    Meta
    first_name = StringField('First Name',[DataRequired(message="Field required")], render_kw={'placeholder': 'First Name'})
    last_name = StringField('Last Name',[DataRequired(message="Field required")], render_kw={'placeholder': 'Last Name'})
    username = StringField('Username',[DataRequired(message="Field required")], render_kw={'placeholder': 'Username'})
    password = PasswordField('Password', [DataRequired(message="Field required",),EqualTo('confirm_password', message='Passwords must match'),Regexp("[A-Za-z0-9]{8,}$", message='Password must contain at least 8 characters, 1 uppercase, 1 lowercase and 1 number.')], render_kw={'placeholder': 'Password (Must contain 1 uppercase, 1 lowercase and 1 number)'})
    confirm_password = PasswordField('Confirm Password',[DataRequired(message="Field required")], render_kw={'placeholder': 'Confirm Password'})
    submit = SubmitField('Sign Up')

class IndexForm(FlaskForm):
    Meta
    login = FormField(LoginForm, [DataRequired(message="Field required")])
    register = FormField(RegisterForm, [DataRequired(message="Field required")])

class PostForm(FlaskForm):
    Meta
    content = TextAreaField('New Post', render_kw={'placeholder': 'What are you thinking about?'})
    image = FileField('Image')
    submit = SubmitField('Post')

class CommentsForm(FlaskForm):
    Meta
    comment = TextAreaField('New Comment', render_kw={'placeholder': 'What do you have to say?'})
    submit = SubmitField('Comment')

class FriendsForm(FlaskForm):
    Meta
    username = StringField('Friend\'s username', render_kw={'placeholder': 'Username'})
    submit = SubmitField('Add Friend')

class ProfileForm(FlaskForm):
    Meta
    education = StringField('Education', render_kw={'placeholder': 'Highest education'})
    employment = StringField('Employment', render_kw={'placeholder': 'Current employment'})
    music = StringField('Favorite song', render_kw={'placeholder': 'Favorite song'})
    movie = StringField('Favorite movie', render_kw={'placeholder': 'Favorite movie'})
    nationality = StringField('Nationality', render_kw={'placeholder': 'Your nationality'})
    birthday = DateField('Birthday')
    submit = SubmitField('Update Profile')
