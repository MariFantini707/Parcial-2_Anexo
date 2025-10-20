from flask import Flask, request, session, redirect, url_for, flash, render_template
import sqlite3
import os
import bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired
from flask_talisman import Talisman  # Importar Flask-Talisman

# Inicializar la app y protección CSRF
app = Flask(__name__)
app.secret_key = os.urandom(24)
csrf = CSRFProtect(app)

# Configuración de Flask-Talisman para CSP
csp = {
    'default-src': ['\'self\''],
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
}

# Aplicar CSP a la aplicación Flask
talisman = Talisman(app, content_security_policy=csp)

# Suprimir el encabezado "Server" usando un hook de respuesta
@app.after_request
def remove_server_header(response):
    response.headers['Server'] = 'GenericServer'
    return response

# Conexión a la base de datos
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Función para hash de contraseñas con bcrypt
def hash_password(password):
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password

# Función para verificar contraseña con bcrypt
def check_password(stored_password, provided_password):
    provided_password_bytes = provided_password.encode('utf-8')
    return bcrypt.checkpw(provided_password_bytes, stored_password)

# Clase de formulario de Login con Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

# Página de inicio
@app.route('/')
def index():
    return 'Welcome to the Task Manager Application!'

# Ruta de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Crear el formulario aquí
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

    # Pasa el formulario al render_template
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


