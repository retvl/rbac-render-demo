"""
🚀 RBAC Demo - Развертывание на Render.com
Сайт будет доступен 24/7 по адресу: ваш-проект.onrender.com
"""

import os
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)

# Конфигурация для Render
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-2024')

# Используем PostgreSQL на Render, SQLite локально
if os.environ.get('RENDER'):
    # На Render используем PostgreSQL
    database_url = os.environ.get('DATABASE_URL')
    if database_url and database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Локально используем SQLite
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rbac.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Модели данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Пользователь')
    email = db.Column(db.String(120), unique=True, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Определение прав
ROLE_PERMISSIONS = {
    'Гость': ['Просмотр'],
    'Пользователь': ['Просмотр', 'Редактирование профиля', 'Создание контента'],
    'Модератор': ['Просмотр', 'Редактирование профиля', 'Модерация контента', 
                  'Просмотр пользователей', 'Редактирование ролей'],
    'Администратор': ['Просмотр', 'Редактирование профиля', 'Модерация контента',
                      'Просмотр пользователей', 'Редактирование ролей', 
                      'Удаление пользователей', 'Просмотр логов', 'Управление системой']
}

# Главная страница
@app.route('/')
def index():
    """Главная страница с информацией о проекте"""
    return render_template('index.html', 
                          deployed_on_render=True,
                          site_url=request.host_url)

# Страница входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            # Логируем вход
            log = AuditLog(
                username=user.username,
                action=f"Пользователь {user.username} вошел в систему"
            )
            db.session.add(log)
            db.session.commit()
            
            flash(f'Добро пожаловать, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Неверное имя пользователя или пароль', 'danger')
    
    return render_template('login.html')

# Панель управления
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html',
                          user=user,
                          permissions=ROLE_PERMISSIONS.get(user.role, []))

# Панель администратора
@app.route('/admin')
def admin_panel():
    if 'user_id' not in session or session['role'] != 'Администратор':
        flash('Недостаточно прав для доступа', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    
    return render_template('admin.html', users=users, logs=logs)

# Выход
@app.route('/logout')
def logout():
    if 'username' in session:
        # Логируем выход
        log = AuditLog(
            username=session['username'],
            action=f"Пользователь {session['username']} вышел из системы"
        )
        db.session.add(log)
        db.session.commit()
    
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

# Инициализация базы данных
def init_database():
    """Создание тестовых пользователей"""
    with app.app_context():
        db.create_all()
        
        # Проверяем, есть ли уже администратор
        if not User.query.filter_by(username='admin').first():
            print("🔄 Создание тестовых пользователей...")
            
            # Тестовые пользователи
            users = [
                ('admin', 'admin123', 'Администратор', 'admin@example.com'),
                ('moderator', 'moderator123', 'Модератор', 'moderator@example.com'),
                ('user', 'user123', 'Пользователь', 'user@example.com'),
                ('guest', 'guest123', 'Гость', 'guest@example.com')
            ]
            
            for username, password, role, email in users:
                user = User(username=username, role=role, email=email)
                user.set_password(password)
                db.session.add(user)
            
            db.session.commit()
            print("✅ Тестовые пользователи созданы!")

# Инициализируем БД при запуске
init_database()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)