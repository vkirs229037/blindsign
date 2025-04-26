from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[DataRequired("Введите имя пользователя")])
    password = PasswordField("Пароль", validators=[DataRequired("Введите пароль")], )
    submit = SubmitField()
