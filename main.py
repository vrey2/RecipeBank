from flask import Flask
from sqlalchemy import select
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_bootstrap import Bootstrap
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink

app = Flask(__name__)
bcrypt = Bcrypt(app)
boot = Bootstrap(app)
app.config['FLASK_ADMIN_SWATCH'] = 'flatly'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.sqlite'
app.config['SECRET_KEY'] = 'secretKey'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class User(db.Model, UserMixin):
    id = db.Column('id', db.Integer, primary_key=True)
    username = db.Column('username', db.String(100))
    password = db.Column('password', db.String(100))

class Recipe(db.Model):
    __tablename__='Recipes'
    id = db.Column('id', db.Integer, primary_key= True)
    name = db.Column('name', db.String(150))
    serving = db.Column('serve', db.Integer())
    prep = db.Column('prep', db.String(100))
    cook = db.Column('cook', db.String(100))
    ingredients = db.Column('ingr', db.String(1000))
    instruction = db.Column('instr', db.String(1000))
    time = db.Column('time', db.String(100))
    user = db.relationship('User', backref=db.backref('Recipe', uselist=False))

class MyModelView(ModelView):
    def is_accessible(self):
        if (current_user.is_authenticated):
            isUser = User.query.filter_by(user_id=current_user.id).first()
            if (not (isUser)):
                return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        if (current_user.is_authenticated):
            isUser = User.query.filter_by(user_id=current_user.id).first()
            if (not (isUser)):
                return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))


admin = Admin(app, index_view=MyAdminIndexView())
admin.add_link(MenuLink(name='Logout', category='', url="/"))


class UsrView(ModelView):
    def is_accessible(self):
        if (current_user.is_authenticated):
            isUser = User.query.filter_by(user_id=current_user.id).first()
            if (not (isUser)):
                return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

    # column_labels = {'Teacher.Name': 'Teacher'}
    # column_list = ['courseName', 'teacher.name', 'numEnrolled', 'capacity', 'time']


class EnrollmentView(ModelView):
    def is_accessible(self):
        if (current_user.is_authenticated):
            isUser = User.query.filter_by(user_id=current_user.id).first()
            if (not (isUser)):
                return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

    # column_list = ['student.name', 'courses.courseName', 'grade']


admin.add_view(MyModelView(User, db.session))
# # admin.add_view(MyModelView(Teacher, db.session))
admin.add_view(UsrView(User, db.session))
#
# # admin.add_view(MyModelView(Student, db.session))
# admin.add_view(StudentView(Student, db.session))
#
# # admin.add_view(ModelView(Courses, db.session))
# admin.add_view(CourseView(Courses, db.session))
# # admin.add_view(ModelView(Enrollment, db.session))
# admin.add_view(EnrollmentView(Enrollment, db.session))

@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        #user = User.query.filter_by(username=form.username.data).first()
        return render_template('home.html')
            # return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/home', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('home.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))