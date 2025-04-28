import os

app_dir = os.path.abspath(os.path.dirname(__file__))

class BaseConfig:
    # Ключ для генерации CSFR-токена
    SECRET_KEY = os.environ.get("SECRET_KEY") or "12345678qwerty"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI") or "sqlite:///" + os.path.dirname(app_dir) + os.path.sep + "data" + os.path.sep + "db.sqlite3"
    NOTARY_PRIVATE_KEY_LOCATION = os.environ.get("NOTARY_PRIVATE_KEY_LOCATION") or os.path.dirname(app_dir) + os.path.sep + "data" + os.path.sep + "keys.pem"
    NOTARY_PUBLIC_KEY_LOCATION = os.environ.get("NOTARY_PUBLIC_KEY_LOCATION") or os.path.dirname(app_dir) + os.path.sep + "data" + os.path.sep + "pk.pem"
    NOTARY_PASSWORD = os.environ.get("NOTARY_PASSWORD") or "12345678"
    UPLOADS_PATH = os.path.join(app_dir, "..", "data")
    LOG_FILE = os.path.join(app_dir, "..", "log.txt")