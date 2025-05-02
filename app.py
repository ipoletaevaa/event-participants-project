from flask import Flask, request
from flask import render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import os
import sqlalchemy as sa
from flask_wtf.file import FileAllowed
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import current_user, login_user
from flask_login import logout_user
from flask_login import login_required
from urllib.parse import urlparse
from flask_wtf import FlaskForm
from wtforms import PasswordField, BooleanField
from wtforms.validators import ValidationError, Email, EqualTo
from hashlib import md5
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from wtforms import StringField, TextAreaField, SubmitField, FileField
from wtforms.validators import DataRequired, Length
from flask_bootstrap import Bootstrap
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta
import secrets

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
login = LoginManager(app)
login.login_view = 'login'
app.config['SECRET_KEY'] = 'you-will-never-guess'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
                                        'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bootstrap = Bootstrap(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    about_me = db.Column(db.String(140))
    role = db.Column(db.String(32), default='participant')#добавила
    avatar = db.Column(db.String(120))
    qr_code_token = db.Column(db.String(32), index=True)
    qr_code_token_expiration = db.Column(db.DateTime)

    def avatar_url(self, size=128):
        if self.avatar:
            return url_for('static', filename=f'uploads/avatars/{self.avatar}')
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'

    def __repr__(self):
        return '<User {}>'.format(self.username)

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
        if self.qr_code_token == token and self.qr_code_token_expiration > datetime.utcnow():
            return True
        return False

    def get_qr_code(self):
        if not self.qr_code_token or self.qr_code_token_expiration < datetime.utcnow():
            self.generate_qr_token()

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr_data = f"{self.id}:{self.qr_code_token}"
        qr.add_data(qr_data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"

    #методы для проверки роли
    def is_admin(self):
        return self.role == 'admin'

    def is_expert(self):
        return self.role == 'expert'

    def is_organizer(self):
        return self.role == 'organizer'

    def is_participant(self):
        return self.role == 'participant'


@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))

class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    email = StringField('Адрес электронной почты', validators=[DataRequired(), Email()])
    password = PasswordField('Придумайте пароль', validators=[DataRequired()])
    password2 = PasswordField(
        'Повторите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Подтвердить')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Это имя уже занято.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('К этому адресу электронной почты уже привязан аккаунт.')

class EditProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    about_me = TextAreaField('Обо мне', validators=[Length(min=0, max=140)])
    avatar = FileField('Фото профиля', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    remove_avatar = BooleanField('Удалить фото профиля')
    submit = SubmitField('Подтвердить изменения')

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError('Это имя уже занято')

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}

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
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data):
            flash('Неправильный логин или пароль')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        parsed_url = urlparse(next_page)
        if not next_page or parsed_url.netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
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
        flash('Вы зарегистрированы')
        return redirect(url_for('login'))
    return render_template('register.html', title='Регистрация', form=form)

@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    return redirect(url_for('edit_profile_with_username', username=current_user.username))

@app.route('/edit_profile/<username>', methods=['GET', 'POST'])
@login_required
def edit_profile_with_username(username):
    user = User.query.filter_by(username=username).first_or_404()
    is_owner = current_user.id == user.id

    qr_token = request.args.get('qr_token')
    has_qr_access = False

    if qr_token and user.check_qr_token(qr_token):
        has_qr_access = True
    elif not is_owner:
        flash('У вас нет прав для редактирования этого профиля', 'error')
        return redirect(url_for('index'))

    form = EditProfileForm(user.username)

    if form.validate_on_submit():
        if has_qr_access:
            if form.username.data != user.username:
                flash('Вы не можете изменять имя пользователя с временным доступом', 'error')
                return redirect(url_for('edit_profile_with_username', username=user.username, qr_token=qr_token))
        else:
            user.username = form.username.data

        user.about_me = form.about_me.data

        if form.remove_avatar.data and user.avatar:
            avatar_path = os.path.join(basedir, 'static', 'uploads', 'avatars')
            old_avatar = os.path.join(avatar_path, user.avatar)
            if os.path.exists(old_avatar):
                os.remove(old_avatar)
            user.avatar = None
        elif form.avatar.data:
            avatar = form.avatar.data
            filename = secure_filename(f"{user.id}_{avatar.filename}")
            avatar_path = os.path.join(basedir, 'static', 'uploads', 'avatars')
            os.makedirs(avatar_path, exist_ok=True)
            avatar.save(os.path.join(avatar_path, filename))
            if user.avatar:
                old_avatar = os.path.join(avatar_path, user.avatar)
                if os.path.exists(old_avatar):
                    os.remove(old_avatar)
            user.avatar = filename

        db.session.commit()
        flash('Изменения успешно сохранены')

        if has_qr_access:
            return redirect(url_for('edit_profile_with_username', username=user.username, qr_token=qr_token))
        return redirect(url_for('edit_profile_with_username', username=user.username))

    elif request.method == 'GET':
        form.username.data = user.username
        form.about_me.data = user.about_me

    return render_template(
        'edit_profile.html',
        title='Редактировать профиль',
        form=form,
        user=user,
        is_owner=is_owner,
        has_qr_access=has_qr_access
    )

@app.route('/generate_qr', methods=['GET', 'POST'])
@login_required
def generate_qr():
    current_user.generate_qr_token()
    expiration_time = (datetime.utcnow() + timedelta(hours=1)).strftime('%H:%M')
    return render_template('qr_code.html',
                         title='Мой QR-код',
                         expiration_time=expiration_time)

@app.route('/scan_qr', methods=['GET', 'POST'])
@login_required
def scan_qr():
    if request.method == 'POST':
        qr_data = request.form.get('qr_data')
        if not qr_data:
            flash('Не удалось прочитать QR-код')
            return redirect(url_for('scan_qr'))

        try:
            user_id, token = qr_data.split(':')
            user = User.query.get(int(user_id))
            if user and user.check_qr_token(token):
                return redirect(url_for(
                    'edit_profile_with_username',
                    username=user.username,
                    qr_token=token
                ))
            else:
                flash('Недействительный или просроченный QR-код')
        except (ValueError, AttributeError):
            flash('Неверный формат QR-кода')

        return redirect(url_for('scan_qr'))

    return render_template('scan_qr.html', title='Сканировать QR-код')

if __name__ == '__main__':
    app.run(debug=True)
