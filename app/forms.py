from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[DataRequired("Введите имя пользователя")])
    password = PasswordField("Пароль", validators=[DataRequired("Введите пароль")], )
    submit = SubmitField()

class RegisterForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[DataRequired("Введите имя пользователя")])
    name = StringField("Отображаемое имя", validators=[DataRequired("Введите ваше имя")])
    password = PasswordField("Пароль", validators=[DataRequired("Введите пароль")])
    repeat_password = PasswordField("Повторите пароль", validators=[DataRequired("Введите пароль еще раз")])
    submit = SubmitField()