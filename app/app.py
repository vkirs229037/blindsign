from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, current_user, login_required

app = Flask(__name__)
app.debug = True
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////home/vl/Универ/Семестр 8/КМЗИ/Практики/РЗ/data/users.db"
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(username: str):
    return db.session.query(User).get(username)

class User(db.Model, UserMixin):
    __tablename__ = "Users"
    username = db.Column(db.String(64), nullable = False, primary_key = True)
    name = db.Column(db.String(128), nullable = False)
    password_hash = db.Column(db.String(100), nullable = False)

    def __repr__(self):
        return f"<User: {self.id}, {self.name} ({self.username})>"
    
    def set_pw(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_pw(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)
    

class Transaction(db.Model):
    __tablename__ = "Transactions"
    username1 = db.Column(db.String(64), primary_key = True)
    username2 = db.Column(db.String(64), primary_key = True)
    date = db.Column(db.Date())
    successful = db.Column(db.Boolean())

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/")
@login_required
def index():
    return render_template("main.html")