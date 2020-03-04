import os
from mail import app
from flask_nav import Nav
from flask_wtf import Form
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask import redirect, url_for, request, render_template, flash, session
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, InputRequired, Length, ValidationError, Email
from flask_nav.elements import Navbar, View, Subgroup
from flask_login import login_required, LoginManager, login_user, UserMixin, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash


bootstrap = Bootstrap(app)
login_manager = LoginManager()

login_manager.login_view = 'index'
login_manager.init_app(app)

nav = Nav()

@nav.navigation()
def mynavbar():
    return Navbar(
        'VR-Project',
        View('Home', 'index'),
        View('Signup', 'signup'),
        Subgroup(
            'DBread',
            View('Mono-Db','dbread'),
            View('Poly-Db','all'),
        ),
        View('Logout', 'logout'),
    )

nav.init_app(app)

basedir = os.path.abspath('')

app.config['SECRET_KEY']='Thisissceretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir,'login.db')
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False


db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(25))
    mail = db.Column(db.String(40))



#======================================FORM=======================================
class LoginForm(Form):
    username = StringField('username', validators=[InputRequired('Username is Required'),Length(min=8,max=15,message='Must be between 8 to 12 characters')])
    password = PasswordField('password', validators=[DataRequired('Password is Required'),Length(min=8,max=15,message='Password required atleast 8 to 12 characters ')])
    submit = SubmitField("Login")

class SignUp(Form):
    username = StringField('username', validators=[InputRequired('Username is Required'),Length(min=8,max=15,message='Must be between 8 to 12 characters')])
    password = PasswordField('password', validators=[DataRequired('Password is Required'),Length(min=8,max=15,message='Password required atleast 8 to 12 characters ')])
    email = StringField('email-id',validators=[Email('use valid email address')])
    sign = SubmitField('Signup')
    submit = SubmitField("Signup")

class dbreadF(Form):
    user = StringField('username')
    pwd = StringField('password')
    mail = StringField('email-id')
    Id = StringField('id')
    show = SubmitField('show')
    insert = SubmitField('insert')
    update = SubmitField('update')
    delete = SubmitField('delete')

#======================================FLASK=======================================


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/',methods=['GET','POST'])
def index():
    session['name'] = None
    global form
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                session['name'] = user.username
                login_user(user)
                return redirect(url_for('dbread')) 
        else:
            flash("Username and Password doesn't Match or Exits")
    return  render_template('public/index.html',form = form)

@app.route('/signup', methods=['POST','GET'])
def signup():
    forms = SignUp()
    if request.method == 'POST':
        if forms.validate_on_submit():
            user = User.query.filter_by(username=forms.username.data).first()
            if user == None:
                hash_password = generate_password_hash(forms.password.data, method='sha256')
                user_add = User(username=forms.username.data, password=hash_password, mail=forms.email.data)
                db.session.add(user_add)
                db.session.commit()
                return redirect(url_for('index'))
            flash('Username is already Exits')
    return render_template('public/signup.html',forms = forms)

@app.route('/db/mono',methods=['GET','POST'])
@login_required
def dbread():
    formd = dbreadF()
        
    if not session['name'] == None:
        flash('Welcome %s!. Have a Nice day!'%session.get('name',None))

    if request.method == 'POST':

        name = formd.user.data
        password = formd.pwd.data
        mail = formd.mail.data
        Id = formd.Id.data
        if request.form.get('show') == 'show':
            Id = formd.Id.data
            if Id:
                user =  User.query.get(Id)
                if user:
                    return render_template('public/db.html',formd=formd,user=user)
            flash('Fill the Id number', 'error')
  
        if request.form.get('insert') == 'insert':
            if name and mail:
                user  = User.query.filter_by(username=name).first()
                if user == None:
                    hash_password = generate_password_hash(password, method='sha256')
                    user_insert = User(username=name, password=hash_password, mail=mail)
                    db.session.add(user_insert)
                    db.session.commit()
                    flash('Data inserted','sucess') 
            else:
                flash('Please fill all details or username alread Exits','error')          

        if request.form.get('update') == 'update' :
            if name and mail:
                user = User.query.get(Id)
                user.username = formd.user.data
                user.mail = formd.mail.data
                db.session.commit()
                flash('Data updated','sucess')                
            else:
                flash('Please fill all details','error')    

        if request.form.get('delete') == 'delete' :
            if Id:
                user_add = User.query.get(Id)
                if user_add:
                    db.session.delete(user_add)
                    db.session.commit()
                    flash('Data deleted','sucess')
            else:
                flash('Fill the Id number','error')

    return render_template('public/db.html',formd=formd,user='')


@app.route('/db/all',methods=['POST','GET'])
@login_required
def all():
    return render_template('public/read.html', users = User.query.all())


@app.route('/db/edit_user/<id>',methods=['POST','GET'])
@login_required
def edit_user(id):
    form = dbreadF()
    Id = id
    if request.method == 'POST':
        if form.validate_on_submit():
            if request.form.get('update') == 'update' :
                if form.user.data and form.mail.data:
                    user = User.query.get(Id)
                    user.username = form.user.data
                    user.mail = form.mail.data
                    db.session.commit()
                    flash('Data updated','sucess')
                    return redirect(url_for('all'))               
                else:
                    flash('Please fill all details','error')
            
    return render_template('public/edituser.html',user='',edit_user=True,users = User.query.get(id), form = form)


@app.route('/db/del_user/<id>',methods=['POST','GET'])
@login_required
def del_user(id):
    form = dbreadF()
    Id = id
    if request.method == 'POST':
        if form.validate_on_submit():
            if request.form.get('delete') == 'delete' :
                if Id:
                    user_add = User.query.get(Id)
                    if user_add:
                        db.session.delete(user_add)
                        db.session.commit()
                        flash('Data deleted','sucess')
                        return redirect(url_for('all'))
                else:
                    flash('Fill the Id number','error')
    return render_template('public/edituser.html',user='',del_user=True,users = User.query.get(id), form = form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Bye %s'%session.get('name'))
    return redirect(url_for('index'))
