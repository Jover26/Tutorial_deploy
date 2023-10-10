from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from .forms import LoginForm, RegisterForm
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user
from flask_login import current_user
from . import db
from .models import User
from sqlalchemy.orm.exc import NoResultFound

authbp = Blueprint('auth', __name__)

@authbp.route('/register', methods=['GET', 'POST'])
def register():
    register = RegisterForm()
    
    if register.validate_on_submit():
        user_name = register.user_name.data
        password = register.password.data
        email = register.email_id.data
        print(email)

        user = db.session.scalar(db.select(User).where(User.emailid == email))
        if user:
            error_message = "Email address already exists. Please login instead."
            print("Error:", error_message)
            return render_template('register.html', form=register, heading='Register', error_message=error_message)

        pwd_hash = generate_password_hash(password)
        new_user = User(name=user_name, password_hash=pwd_hash, emailid=email)
        db.session.add(new_user)
        db.session.commit()
        user = db.session.scalar(db.select(User).where(User.emailid==email))
        login_user(user)

        return redirect(url_for('main.index'))

    if request.method == 'POST':
        error_descriptions = [error for errors in register.errors.values() for error in errors]
        error_message = ". ".join(error_descriptions)
        print("Form Errors:", error_message)
        return render_template('register.html', form=register, heading='Register', error_message=error_message)

    return render_template('register.html', form=register, heading='Register')


    
    
@authbp.route('/login', methods=['GET', 'POST'])
def login():
    print("hello")
        
    login_form = LoginForm()
    error = None
    print(login_form.email_id.data)
    print(login_form.password.data)
    if login_form.validate_on_submit():
        email_id = login_form.email_id.data
        password = login_form.password.data
        print(email_id)
        user = db.session.scalar(db.select(User).where(User.emailid == email_id))
        if user is None:
            error = 'Incorrect email or password'
        elif not check_password_hash(user.password_hash, password):
            error = 'Incorrect email or password'
        if error is None:
            login_user(user)
            next_page = session.get('next_page') or '/'
            return redirect(next_page)
        else:
            flash(error)
    return render_template('login.html', form=login_form, heading='Login', error_message=error)

@authbp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))