import sqlite3
from vulnerable_app import hash_password

# Conexión a la base de datos (se creará automáticamente si no existe)
conn = sqlite3.connect('database.db')

# Crear un cursor
c = conn.cursor()

# Guardar los cambios y cerrar la conexión
conn.commit()
conn.close()

def create_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Crear la tabla de usuarios
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # Crear la tabla de tareas
    c.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            task TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Insertar usuarios de ejemplo (contraseñas encriptadas)
    hashed_admin_password = hash_password('adminpassword')
    hashed_user_password = hash_password('userpassword')

    c.execute('''
        INSERT INTO users (username, password, role) VALUES
        ('admin', ?, 'admin'),
        ('user', ?, 'user')
    ''', (hashed_admin_password, hashed_user_password))

    conn.commit()
    conn.close()

print("Base de datos y tablas creadas con éxito.")

