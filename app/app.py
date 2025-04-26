from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user
from forms import LoginForm, RegisterForm

app = Flask(__name__)
app.debug = True
app.config.from_object("config.BaseConfig")
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Войдите в свой аккаунт для доступа к системе."

@login_manager.user_loader
def load_user(username: str):
    return db.session.query(User).get(username)

class User(db.Model, UserMixin):
    __tablename__ = "Users"
    id = db.Column(db.Integer(), nullable = False, primary_key = True)
    username = db.Column(db.String(64), nullable = False, unique = True)
    name = db.Column(db.String(128), nullable = False)
    password_hash = db.Column(db.String(100), nullable = False)

    def __repr__(self):
        return f"<User: {self.id}, {self.name} ({self.username})>"
    
    def set_pw(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_pw(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)
    
notary = User(username="notarius", name="Нотариус")
notary.set_pw(app.config["NOTARY_PASSWORD"])

@app.route("/login", methods=["post", "get"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.username == form.username.data).first()
        if user and user.check_pw(form.password.data):
            flash("Авторизация прошла успешно.", "info")
            login_user(user)
            return redirect(url_for("index"))
        flash("Неверное имя пользователя или пароль.", "error")
        return redirect(url_for("login"))
    
    return render_template("login.html", form=form)

@app.route("/register", methods=["post", "get"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.username == form.username.data).first()
        if user:
            flash("Пользователь уже существует.", "error")
            return redirect(url_for("register"))
        if form.password.data != form.repeat_password.data:
            flash("Пароль был введен неверно.", "error")
            return redirect(url_for("register"))
        
        # здесь user == None
        user = User(username=form.username.data, name=form.name.data)
        user.set_pw(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash("Регистрация прошла успешно.", "info")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/")
@login_required
def index():
    return render_template("index.html", name=current_user.name)