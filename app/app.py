from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from forms import LoginForm, RegisterForm, SignForm, SendForm, PickFileForm
from sign import gen_keys, import_keys, gen_sign, gen_mask, import_public_key, mask_data, get_sign
import os
import base64
from config import app_dir
import time

app = Flask(__name__)
app.debug = True
app.config.from_object("config.BaseConfig")
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Войдите в свой аккаунт для доступа к системе."

def log(level: int, msg: str):
    with open(app.config["LOG_FILE"], "a") as f:
        match level:
            case 0:
                prefix = "[INFO]  "
            case 1:
                prefix = "[ERROR] "
        prefix += time.strftime("%d/%m/%Y %H:%M:%S ")
        f.write(prefix + msg + "\n")

@login_manager.user_loader
def load_user(username: str):
    return db.session.query(User).get(username)

class User(db.Model, UserMixin):
    __tablename__ = "Users"
    id = db.Column(db.Integer(), nullable = False, primary_key = True)
    username = db.Column(db.String(64), nullable = False, unique = True)
    name = db.Column(db.String(128), nullable = False)
    password_hash = db.Column(db.String(256), nullable = False)

    def __repr__(self):
        return f"<User: {self.id}, {self.name} ({self.username})>"
    
    def set_pw(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_pw(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)
    
class Document(db.Model):
    __tablename__ = "Documents"
    id = db.Column(db.Integer(), nullable = False, primary_key = True)
    username = db.Column(db.String(64), nullable = False)
    r = db.Column(db.Text(), nullable = False)
    hash_bytes = db.Column(db.Text(), nullable = False)
    masked_hash = db.Column(db.Text(), nullable = False)
    eds_bytes = db.Column(db.Text(), nullable = True)

@app.route("/login", methods=["post", "get"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.username == form.username.data).first()
        if user and user.check_pw(form.password.data):
            log(0, f"пользователь {user.username} был авторизован")
            flash("Авторизация прошла успешно.", "info")
            login_user(user)
            return redirect(url_for("index"))
        log(1, f"безуспешная попытка авторизации, username={form.username.data}")
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
            log(1, f"безуспешная попытка регистрации")
            flash("Пользователь уже существует.", "error")
            return redirect(url_for("register"))
        if form.password.data != form.repeat_password.data:
            log(1, f"безуспешная попытка регистрации")
            flash("Пароль был введен неверно.", "error")
            return redirect(url_for("register"))
        
        # здесь user == None
        user = User(username=form.username.data, name=form.name.data)
        user.set_pw(form.password.data)
        db.session.add(user)
        db.session.commit()

        log(0, f"пользователь {user.username} зарегистрировался")
        flash("Регистрация прошла успешно.", "info")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/queue")
@login_required
def queue():
    if current_user.username != "notarius":
        flash("Доступ запрещен.", "error")
        return redirect(url_for("index"))
    docs = db.session.query(Document).filter(Document.eds_bytes == None).all()
    return render_template("queue.html", docs=docs)

@app.route("/sign", methods=["post", "get"])
@login_required
def sign():
    if current_user.username != "notarius":
        flash("Доступ запрещен.", "error")
        return redirect(url_for("index"))
    doc_id = request.args["id"]
    doc = db.session.query(Document).filter(Document.id == doc_id).first()
    form = SignForm()
    if form.validate_on_submit():
        password = form.password.data
        rsakey, result = import_keys(app.config["NOTARY_PRIVATE_KEY_LOCATION"], password)
        if not result:
            log(1, f"нотариус неверно ввел пароль")
            flash("Неверный пароль.", "error")
            return redirect(url_for("sign", id=doc_id))
        signature = gen_sign(doc.masked_hash, rsakey.d, rsakey.n)
        doc.eds_bytes = str(signature)
        db.session.add(doc)
        db.session.commit()
        log(0, f"нотариус подписал документ {doc_id}")
        flash("Успешно подписан документ.", "info")
        return redirect(url_for("queue"))
    return render_template("document.html", hash=doc.masked_hash, form=form)

@app.route("/send", methods=["post", "get"])
@login_required
def send():
    if current_user.username == "notarius":
        flash("Доступ запрещен.", "error")
        return redirect(url_for("index"))
    form = SendForm()
    if form.validate_on_submit():
        file = form.file.data
        filepath = os.path.join(app.config["UPLOADS_PATH"], file.filename)
        file.save(filepath)
        with open(filepath, "rb") as f:
            data = f.read()
        rsakey = import_public_key(app.config["NOTARY_PUBLIC_KEY_LOCATION"])
        log(0, f"пользователь {current_user.username} импортировал открытый ключ нотариуса")
        m, r, mprime = mask_data(data, rsakey.n, rsakey.e)
        doc = Document(username = current_user.username, hash_bytes = str(m), r = str(r), masked_hash = str(mprime))
        db.session.add(doc)
        db.session.commit()
        log(0, f"пользователь {current_user.username} отправил документ на подпись")
        flash("Файл успешно отправлен на подпись.", "info")
        return redirect(url_for("send"))
    return render_template("send.html", form=form)

@app.route("/signed")
@login_required
def signed():
    if current_user.username == "notarius":
        flash("Доступ запрещен.", "error")
        return redirect(url_for("index"))
    signed_docs = db.session.query(Document).filter(Document.eds_bytes != None, Document.username == current_user.username).all()
    return render_template("signed.html", docs=signed_docs)

@app.route("/check", methods = ["post", "get"])
@login_required
def check():
    if current_user.username == "notarius":
        flash("Доступ запрещен.", "error")
        return redirect(url_for("index"))
    doc_id = request.args["id"]
    doc = db.session.query(Document).filter(Document.id == doc_id).first()
    rsakey = import_public_key(app.config["NOTARY_PUBLIC_KEY_LOCATION"])
    log(0, f"пользователь {current_user.username} импортировал открытый ключ нотариуса")
    eds, result = get_sign(doc.hash_bytes, doc.eds_bytes, doc.r, rsakey.e, rsakey.n)
    if result:
        log(0, f"пользователь {current_user.username} проверил подпись под документом {doc_id}; подпись корректна")
        flash("Подпись подтверждена и корректна.", "info")
    else:
        log(0, f"пользователь {current_user.username} проверил подпись под документом {doc_id}; подпись некорректна")
        flash("Подпись не подтверждена.", "error")
    eds_b64 = base64.standard_b64encode(eds.to_bytes(256)).decode()
    return render_template("check.html", doc=doc, eds=eds_b64)

@app.route("/")
@login_required
def index():
    return render_template("index.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    log(0, f"пользователь {current_user.username} вышел из системы")
    logout_user()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("login"))

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/settings", methods=["post", "get"])
@login_required
def settings():
    form = PickFileForm()
    if form.validate_on_submit():
        try:
            f = open(form.file.data, "x")
            app.config["LOG_FILE"] = form.file.data
            f.close()
            flash("Успешно изменено расположение файла журнала", "info")
            return redirect(url_for("settings"))
        except (OSError, FileExistsError):
            flash("Файл не мог быть создан.", "error")
            return redirect(url_for("settings"))
    return render_template("settings.html", form=form)

with app.app_context():
    if not os.path.exists(os.path.join(app_dir, "..", "data")):
        os.makedirs(os.path.join(app_dir, "..", "data"))
        log(0, f"создана папка data")
    db.create_all()
    if not db.session.query(User).filter(User.username == "notarius").first():
        notary = User(username="notarius", name="Нотариус")
        notary.set_pw(app.config["NOTARY_PASSWORD"])
        db.session.add(notary)
        db.session.commit()
        log(0, f"создан пользователь нотариус")

    if not os.path.exists(app.config["NOTARY_PRIVATE_KEY_LOCATION"]):
        rsakey = gen_keys()
        with open(app.config["NOTARY_PRIVATE_KEY_LOCATION"], "wb") as f:
            data = rsakey.export_key(passphrase=app.config["NOTARY_PASSWORD"], 
                                    pkcs=8, 
                                    protection="PBKDF2WithHMAC-SHA512AndAES256-CBC", 
                                    prot_params={"iteration_count": 131072})
            f.write(data)
        with open(app.config["NOTARY_PUBLIC_KEY_LOCATION"], "wb") as f:
            data = rsakey.public_key().export_key()
            f.write(data)
        log(0, f"ключи нотариуса сохранены")