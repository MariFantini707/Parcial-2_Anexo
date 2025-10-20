from flask import Flask, request, session, redirect, url_for, flash, render_template
import sqlite3
import os
import bcrypt
from markupsafe import escape
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
    'default-src': ['\'self\''],  # Solo permitir contenido de la misma fuente
    'script-src': ['\'self\'', 'https://trusted-scripts.com'],  # Permitir scripts desde 'self' y un dominio de confianza
    'style-src': ['\'self\'', 'https://trusted-styles.com', 'https://fonts.googleapis.com'],  # Permitir estilos desde 'self' y un dominio de confianza
    'img-src': ['\'self\'', 'https://trusted-images.com'],  # Permitir imágenes desde 'self' y un dominio de confianza
    'font-src': ['\'self\'', 'https://trusted-fonts.com', 'https://fonts.gstatic.com'],  # Permitir fuentes desde 'self' y un dominio de confianza
    'connect-src': ['\'self\''],  # Permitir conexiones XHR desde 'self'
    'frame-src': ['\'self\''],  # Permitir marcos solo desde 'self'
    'object-src': ['\'none\''],  # Deshabilitar los objetos embebidos como applets de Java, Flash, etc.
    'media-src': ['\'self\''],  # Permitir solo medios desde 'self'
    'child-src': ['\'none\''],  # Deshabilitar cargas de contenido en iframes y marcos
    'form-action': ['\'self\''],  # Permitir que los formularios solo apunten a 'self'
    'upgrade-insecure-requests': [],  # Opcional: obliga a actualizar solicitudes HTTP a HTTPS
}

# Aplicar CSP a la aplicación Flask
talisman = Talisman(app, content_security_policy=csp)

# Suprimir el encabezado "Server" usando un hook de respuesta
@app.after_request
def remove_server_header(response):
    response.headers['Server'] = 'GenericServer'  # Modificar el encabezado "Server" a un valor genérico
    return response

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

# Ruta de login
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
