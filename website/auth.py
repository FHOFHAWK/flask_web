from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from .models import User
from website import db

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Успешный вход!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.main_page'))
            else:
                flash('Неверный пароль', category='error')
        else:
            flash('Нет такого пользака', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Пользак уже есть', category='error')
        elif len(email) < 4:
            # TODO: добавить regex на проверку email
            flash('Email не может быть короче 4 символов', category='error')

        elif len(firstName) < 2:
            flash('Имя не может быть короче 2 символов', category='error')

        elif password1 != password2:
            flash('Пароли не совпали', category='error')

        elif len(password1) < 7:
            flash('Пароль не может быть короче 7 символов', category='error')

        else:
            new_user = User(email=email, first_name=firstName,
                            password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Аккаунт успешно создан', category='success')
            return redirect(url_for('views.main_page'))

    return render_template("sign_up.html", user=current_user)
