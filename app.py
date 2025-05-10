from flask import Flask, request, render_template, flash, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from flask_bootstrap import Bootstrap
from hashlib import md5
from urllib.parse import urlparse
from functools import wraps
import sqlalchemy as sa
import qrcode
import base64
from io import BytesIO
from datetime import datetime, timedelta
import secrets
import os

# --- Инициализация ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'you-will-never-guess'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or f'sqlite:///{os.path.join(basedir, "app.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bootstrap = Bootstrap(app)

login = LoginManager(app)
login.login_view = 'login'

# --- Модели ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    about_me = db.Column(db.String(140))
    avatar = db.Column(db.String(120))
    role = db.Column(db.String(20), default='participant')
    qr_code_token = db.Column(db.String(32), index=True)
    qr_code_token_expiration = db.Column(db.DateTime)

    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

    def avatar_url(self, size=128):
        if self.avatar:
            return url_for('static', filename=f'uploads/avatars/{self.avatar}')
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'

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

@login.user_loader
def load_user(id): return db.session.get(User, int(id))

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
            raise ValidationError('Имя занято.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Email уже зарегистрирован.')

class EditProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    about_me = TextAreaField('Обо мне', validators=[Length(min=0, max=140)])
    avatar = FileField('Фото профиля', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    remove_avatar = BooleanField('Удалить фото')
    submit = SubmitField('Сохранить')

    def __init__(self, original_username, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username and User.query.filter_by(username=username.data).first():
            raise ValidationError('Имя занято.')

# --- Декоратор ролей ---
def role_required(*roles):
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                abort(403)
            return func(*args, **kwargs)
        return wrapped
    return decorator

# --- Маршруты ---
@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html', title='Главная')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(sa.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data):
            flash('Неверный логин или пароль')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        return redirect(next_page if next_page and urlparse(next_page).netloc == '' else url_for('index'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Вы зарегистрированы')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=user)

@app.route('/change_role/<username>', methods=['POST'])
@login_required
@role_required('admin')
def change_role_from_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    new_role = request.form.get('new_role')
    if new_role in ['admin', 'expert', 'organizer', 'participant']:
        user.role = new_role
        db.session.commit()
        flash(f'Роль пользователя обновлена на {new_role}')
    return redirect(url_for('user', username=user.username))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    return redirect(url_for('edit_profile_with_username', username=current_user.username))

@app.route('/edit_profile/<username>', methods=['GET', 'POST'])
@login_required
def edit_profile_with_username(username):
    user = User.query.filter_by(username=username).first_or_404()
    if current_user.id != user.id:
        flash('Нет доступа')
        return redirect(url_for('index'))

    form = EditProfileForm(user.username)
    if form.validate_on_submit():
        user.username = form.username.data
        user.about_me = form.about_me.data

        avatar_path = os.path.join(basedir, 'static/uploads/avatars')
        os.makedirs(avatar_path, exist_ok=True)

        if form.remove_avatar.data and user.avatar:
            old_path = os.path.join(avatar_path, user.avatar)
            if os.path.exists(old_path): os.remove(old_path)
            user.avatar = None
        elif form.avatar.data:
            filename = secure_filename(f"{user.id}_{form.avatar.data.filename}")
            full_path = os.path.join(avatar_path, filename)
            form.avatar.data.save(full_path)
            if user.avatar:
                old_path = os.path.join(avatar_path, user.avatar)
                if os.path.exists(old_path): os.remove(old_path)
            user.avatar = filename

        db.session.commit()
        flash('Изменения сохранены')
        return redirect(url_for('user', username=user.username))

    elif request.method == 'GET':
        form.username.data = user.username
        form.about_me.data = user.about_me

    return render_template('edit_profile.html', form=form, user=user)

@app.route('/generate_qr')
@login_required
def generate_qr():
    token = current_user.generate_qr_token()
    return render_template('qr_code.html', qr_code=current_user.get_qr_code())

@app.route('/scan_qr', methods=['GET', 'POST'])
@login_required
def scan_qr():
    if request.method == 'POST':
        qr_data = request.form.get('qr_data')
        try:
            user_id, token = qr_data.split(':')
            user = User.query.get(int(user_id))
            if user and user.check_qr_token(token):
                return redirect(url_for('edit_profile_with_username', username=user.username))
            flash('Недействительный или просроченный QR-код')
        except:
            flash('Неверный формат QR-кода')
    return render_template('scan_qr.html')

if __name__ == '__main__':
    app.run(debug=True)
