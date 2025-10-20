from flask import Flask, request, session, redirect, url_for, flash, render_template
import sqlite3
import os
import bcrypt
from markupsafe import escape
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired
from flask_talisman import Talisman  

from functools import wraps
from flask_wtf.csrf import CSRFProtect, generate_csrf
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

#estos los entrega el tutorial de auth0
import json
from os import environ as env
from urllib.parse import quote_plus, urlencode

app = Flask(__name__)
app.secret_key = os.urandom(24)
csrf = CSRFProtect(app)

# Configuración de Flask-Talisman para CSP
csp = {
    'default-src': ['\'self\''],  # Solo permitir contenido de la misma fuente
    'script-src': ['\'self\'', 'https://trusted-scripts.com'],  
    'style-src': ['\'self\'', 'https://trusted-styles.com', 'https://fonts.googleapis.com'], 
    'img-src': ['\'self\'', 'https://trusted-images.com'],
    'font-src': ['\'self\'', 'https://trusted-fonts.com', 'https://fonts.gstatic.com'], 
    'connect-src': ['\'self\''],  
    'frame-src': ['\'self\''],  
    'object-src': ['\'none\''], 
    'media-src': ['\'self\''],  
    'child-src': ['\'none\''],  
    'form-action': ['\'self\''],  
    'upgrade-insecure-requests': [],  
    'manifest-src': ['\'self\''], 
    'worker-src': ['\'self\''], 
}


talisman = Talisman(app, content_security_policy=csp)


@app.after_request
def remove_server_header(response):
    response.headers['Server'] = 'GenericServer'  # Cambia el encabezado "Server" a un valor genérico según lo que me pido ZAP (pero aún da error...)
    return response

# PARTE NUEVA PARA AUTH 

# Cargar variables de entorno (usa un .env en desarrollo o variables de entorno en producción)
load_dotenv()

# Configuración desde variables de entorno
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")  
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
AUTH0_CALLBACK_URL = os.getenv("AUTH0_CALLBACK_URL", "http://localhost:5000/callback")

# Inicializar OAuth (Auth0)
oauth = OAuth(app)
oauth.register(
    name="auth0",
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    server_metadata_url=f"https://{AUTH0_DOMAIN}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
)

# Configuración de sesión / cookies recomendadas
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# app.config["SESSION_COOKIE_SECURE"] = True  # activar en HTTPS en producción

# Decorador opcional para proteger rutas
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth0_login'))
        return f(*args, **kwargs)
    return decorated

# Helper: mapear o crear un usuario local a partir de userinfo de Auth0
def get_or_create_local_user(userinfo):
    username = userinfo.get('email') or userinfo.get('sub')
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    if user:
        conn.close()
        return user
    # Crear usuario local con password vacío (porque autenticamos por Auth0)
    cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, "", "user"))
    conn.commit()
    user_id = cur.lastrowid
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    new_user = cur.fetchone()
    conn.close()
    return new_user

# Ruta para iniciar login con Auth0
@app.route('/auth/login')
def auth0_login():
    # redirige a Auth0 para autenticación
    return oauth.auth0.authorize_redirect(AUTH0_CALLBACK_URL)

# Callback que Auth0 redirige después de autenticar
@app.route('/callback')
def callback_handling():
    # obtener token y claims
    token = oauth.auth0.authorize_access_token()
    # parse_id_token para obtener claims (sub, email, name, ...)
    userinfo = oauth.auth0.parse_id_token(token)
    # almacenar información en session
    session['user'] = {
        'sub': userinfo.get('sub'),
        'name': userinfo.get('name'),
        'email': userinfo.get('email'),
    }
    # mapear/crear usuario local y tomar su id/role para asociar tareas
    local_user = get_or_create_local_user(userinfo)
    if local_user:
        # si local_user es Row (sqlite3.Row) accedemos por columnas
        session['user_id'] = local_user['id']
        session['role'] = local_user['role']
    else:
        # fallback: no pudo mapear, limpiar sesión parcial
        session.pop('user_id', None)
        session['role'] = 'user'
    return redirect(url_for('dashboard'))

# Logout que limpia sesión local y redirige a logout de Auth0
@app.route('/auth/logout')
def auth0_logout():
    session.clear()
    return_to = url_for('index', _external=True)
    logout_url = f"https://{AUTH0_DOMAIN}/v2/logout?client_id={AUTH0_CLIENT_ID}&returnTo={return_to}"
    return redirect(logout_url)


# Conexión a la base de datos
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Función para hash de contraseñas con bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

# Función para verificar contraseña con bcrypt
def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

# Clase de formulario de Login con Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

# Página de inicio
@app.route('/')
def index():
    return 'Welcome to the Task Manager Application!'

# Ruta de login (local)
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        query = "SELECT * FROM users WHERE username = ?"
        user = conn.execute(query, (username,)).fetchone()

        if user and check_password(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

# Ruta de dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    tasks = conn.execute(
        "SELECT * FROM tasks WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()

    return render_template('dashboard.html', user_id=user_id, tasks=tasks)

# Ruta para agregar tarea
@app.route('/add_task', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task = request.form['task']
    user_id = session['user_id']

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO tasks (user_id, task) VALUES (?, ?)", (user_id, task))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))

# Ruta para eliminar tarea
@app.route('/delete_task/<int:task_id>')
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))

# Ruta de admin
@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    return 'Welcome to the admin panel!'

if __name__ == '__main__':
    app.run(debug=True)


@app.after_request
def remove_server_header(response):
    response.headers['Server'] = ''
    return response

