from flask import Flask, request, render_template, flash, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.file import FileAllowed
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import PasswordField, BooleanField, StringField, TextAreaField, SubmitField, FileField
from wtforms.validators import ValidationError, Email, EqualTo, DataRequired, Length
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from flask_bootstrap import Bootstrap
from urllib.parse import urlparse
from hashlib import md5
from functools import wraps
import os, sqlalchemy as sa, qrcode, base64, secrets
from io import BytesIO
from datetime import datetime, timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'you-will-never-guess'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
                                        'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'
bootstrap = Bootstrap(app)

# --- Модель пользователя ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    about_me = db.Column(db.String(140))
    avatar = db.Column(db.String(120))
    qr_code_token = db.Column(db.String(32), index=True)
    qr_code_token_expiration = db.Column(db.DateTime)
    role = db.Column(db.String(20), default='participant')  # 👈 добавлено поле роли

    def avatar_url(self, size=128):
        if self.avatar:
            return url_for('static', filename=f'uploads/avatars/{self.avatar}')
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_qr_token(self, expires_in=3600):
        self.qr_code_token = secrets.token_hex(16)
        self.qr_code_token_expiration = datetime.utcnow() + timedelta(seconds=expires_in)
        db.session.add(self)
        db.session.commit()
        return self.qr_code_token

    def revoke_qr_token(self):
        self.qr_code_token_expiration = datetime.utcnow() - timedelta(seconds=1)
        db.session.add(self)
        db.session.commit()

    def check_qr_token(self, token):
        return self.qr_code_token == token and self.qr_code_token_expiration > datetime.utcnow()

    def get_qr_code(self):
        if not self.qr_code_token or self.qr_code_token_expiration < datetime.utcnow():
            self.generate_qr_token()
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(f"{self.id}:{self.qr_code_token}")
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        return f"data:image/png;base64,{base64.b64encode(buffered.getvalue()).decode()}"

# --- Загрузка пользователя ---
@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))

# --- Декоратор проверки роли ---
def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return wrapper

# --- Формы ---
class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    password2 = PasswordField('Повторите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Это имя уже занято.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Этот email уже используется.')

class EditProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    about_me = TextAreaField('О себе', validators=[Length(0, 140)])
    avatar = FileField('Фото', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    remove_avatar = BooleanField('Удалить фото')
    submit = SubmitField('Сохранить')

    def __init__(self, original_username, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            if User.query.filter_by(username=username.data).first():
                raise ValidationError('Имя уже занято.')

# --- Обработчики ---
@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html', title='Главная')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(sa.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data):
            flash('Неверные данные')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        return redirect(next_page or url_for('index'))
    return render_template('login.html', title='Вход', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация завершена')
        return redirect(url_for('login'))
    return render_template('register.html', title='Регистрация', form=form)

@app.route('/user/<username>')
@login_required
def user(username):
    u = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=u)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    return redirect(url_for('edit_profile_with_username', username=current_user.username))

@app.route('/edit_profile/<username>', methods=['GET', 'POST'])
@login_required
def edit_profile_with_username(username):
    user = User.query.filter_by(username=username).first_or_404()
    is_owner = current_user.id == user.id
    form = EditProfileForm(user.username)
    if form.validate_on_submit():
        if is_owner:
            user.username = form.username.data
        user.about_me = form.about_me.data
        if form.remove_avatar.data and user.avatar:
            avatar_path = os.path.join(basedir, 'static', 'uploads', 'avatars')
            os.remove(os.path.join(avatar_path, user.avatar))
            user.avatar = None
        elif form.avatar.data:
            filename = secure_filename(f"{user.id}_{form.avatar.data.filename}")
            path = os.path.join(basedir, 'static', 'uploads', 'avatars')
            os.makedirs(path, exist_ok=True)
            form.avatar.data.save(os.path.join(path, filename))
            user.avatar = filename
        db.session.commit()
        return redirect(url_for('user', username=user.username))
    elif request.method == 'GET':
        form.username.data = user.username
        form.about_me.data = user.about_me
    return render_template('edit_profile.html', user=user, form=form, is_owner=is_owner)

@app.route('/change_role/<username>', methods=['POST'])
@login_required
@role_required('admin')
def change_role_from_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    new_role = request.form.get('new_role')
    if new_role in ['admin', 'expert', 'organizer', 'participant']:
        user.role = new_role
        db.session.commit()
        flash(f'Роль {user.username} обновлена на {new_role}')
    return redirect(url_for('user', username=user.username))

@app.route('/generate_qr')
@login_required
def generate_qr():
    current_user.generate_qr_token()
    return render_template('qr_code.html', qr_code=current_user.get_qr_code())

@app.route('/scan_qr', methods=['GET', 'POST'])
@login_required
def scan_qr():
    if request.method == 'POST':
        data = request.form.get('qr_data')
        try:
            user_id, token = data.split(':')
            user = User.query.get(int(user_id))
            if user and user.check_qr_token(token):
                return redirect(url_for('edit_profile_with_username', username=user.username, qr_token=token))
            flash('Недействительный токен')
        except:
            flash('Ошибка формата')
        return redirect(url_for('scan_qr'))
    return render_template('scan_qr.html')

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}
