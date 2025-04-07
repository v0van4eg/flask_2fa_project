from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'super_secret_key_123!'  # Обязательно замените в продакшене!
app.permanent_session_lifetime = timedelta(minutes=5)

# База данных пользователей (временная)
users_db = {
    "user1": {
        "password": "pass123",
        "totp_secret": None,  # Здесь будет ключ для 2FA
        "2fa_enabled": False  # Флаг включения 2FA
    },
    "user2": {
        "password": "pass123",
        "totp_secret": None,
        "2fa_enabled": False
    }
}

@app.route('/')
def home():
    # Жёсткая проверка: если нет 2FA или не вошли - на логин
    if not session.get('2fa_verified'):
        return redirect(url_for('login'))
    return render_template('hello.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Проверяем пользователя
        user = users_db.get(username)
        if not user or user['password'] != password:
            flash("Неверный логин или пароль!")
            return redirect(url_for('login'))

        # Сохраняем имя пользователя в сессии
        session['user'] = username
        session['logged_in'] = True

        # Если 2FA включена - запрашиваем код
        if user['2fa_enabled'] and user['totp_secret']:
            return redirect(url_for('verify_2fa'))

        # Если 2FA отключена - перенаправляем на настройку 2FA
        return redirect(url_for('setup_2fa'))

    return render_template('login.html')

@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    username = session.get('user')
    if not username:
        return "Ошибка сессии!"

    if request.method == 'POST':
        # Генерируем и сохраняем секрет
        secret = pyotp.random_base32()
        users_db[username]['totp_secret'] = secret
        users_db[username]['2fa_enabled'] = True

        # Создаём QR-код
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="Моё приложение"
        )

        # Добавляем отладочные сообщения
        print(f"QR Code URI: {totp_uri}")
        print(f"Secret: {secret}")

        # Генерируем QR-код и сохраняем его в сессии
        img = qrcode.make(totp_uri)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        return render_template('setup_2fa.html',
                               qr_code=img_str,
                               secret=secret)

    # Добавляем отладочное сообщение для GET-запроса
    print("GET запрос на /setup_2fa")

    return render_template('setup_2fa.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    # Проверяем, что пользователь на шаге 2FA
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    secret = users_db[username]['totp_secret']

    if request.method == 'POST':
        user_code = request.form.get('2fa_code')
        if not user_code:
            flash("Введите код!")
            return redirect(url_for('verify_2fa'))

        # Проверяем код
        totp = pyotp.TOTP(secret)
        if totp.verify(user_code, valid_window=1):
            session['2fa_verified'] = True  # Критично!
            return redirect(url_for('home'))
        else:
            flash("Неверный код 2FA!")

    return render_template('verify_2fa.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)