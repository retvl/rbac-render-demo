"""
🚀 RBAC Demo - Веб-приложение с системой ролей
Развернуто на Render.com
"""

import os
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)

# Конфигурация приложения
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-2024-rbac')

# Конфигурация базы данных для Render и локальной разработки
if os.environ.get('RENDER'):
    # На Render.com
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Используем PostgreSQL
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        print("✅ Используем PostgreSQL на Render")
    else:
        # Если нет PostgreSQL, используем SQLite во временной директории
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/rbac_demo.db'
        print("⚠️ Используем SQLite во временной директории")
else:
    # Локальная разработка
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rbac_demo.db'
    print("✅ Используем локальную SQLite базу данных")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация базы данных
db = SQLAlchemy(app)

# Модели данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Пользователь')
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Определение прав для ролей
ROLE_PERMISSIONS = {
    'Гость': [
        'Просмотр публичного контента',
        'Регистрация',
        'Вход в систему'
    ],
    'Пользователь': [
        'Просмотр публичного контента',
        'Регистрация',
        'Вход в систему',
        'Редактирование профиля',
        'Создание контента',
        'Просмотр личного кабинета'
    ],
    'Модератор': [
        'Просмотр публичного контента',
        'Регистрация',
        'Вход в систему',
        'Редактирование профиля',
        'Создание контента',
        'Просмотр личного кабинета',
        'Модерация контента',
        'Просмотр пользователей',
        'Редактирование ролей пользователей',
        'Управление комментариями'
    ],
    'Администратор': [
        'Просмотр публичного контента',
        'Регистрация',
        'Вход в систему',
        'Редактирование профиля',
        'Создание контента',
        'Просмотр личного кабинета',
        'Модерация контента',
        'Просмотр пользователей',
        'Редактирование ролей пользователей',
        'Управление комментариями',
        'Удаление пользователей',
        'Просмотр логов действий',
        'Управление системой',
        'Настройка прав доступа',
        'Резервное копирование'
    ]
}

# Маршруты
@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница входа"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Сохраняем данные в сессии
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            # Логируем вход
            log_entry = AuditLog(
                username=user.username,
                action=f"Пользователь {user.username} вошел в систему"
            )
            db.session.add(log_entry)
            db.session.commit()
            
            flash(f'Добро пожаловать, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Неверное имя пользователя или пароль', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """Панель управления"""
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html',
                          user=user,
                          permissions=ROLE_PERMISSIONS.get(user.role, []))

@app.route('/admin')
def admin_panel():
    """Панель администратора"""
    if 'user_id' not in session or session['role'] != 'Администратор':
        flash('Недостаточно прав для доступа к панели администратора', 'danger')
        return redirect(url_for('dashboard'))
    
    current_user = User.query.get(session['user_id'])
    users = User.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
    
    return render_template('admin.html',
                          current_user=current_user,
                          users=users,
                          logs=logs)

@app.route('/moderator')
def moderator_panel():
    """Панель модератора"""
    if 'user_id' not in session or session['role'] != 'Модератор':
        flash('Недостаточно прав для доступа к панели модератора', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get(session['user_id'])
    users = User.query.filter(User.role.in_(['Гость', 'Пользователь'])).all()
    
    return render_template('moderator.html',
                          user=user,
                          users=users)

@app.route('/user/profile')
def user_profile():
    """Профиль пользователя"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('user.html', user=user)

@app.route('/logout')
def logout():
    """Выход из системы"""
    if 'username' in session:
        # Логируем выход
        log_entry = AuditLog(
            username=session['username'],
            action=f"Пользователь {session['username']} вышел из системы"
        )
        db.session.add(log_entry)
        db.session.commit()
        
        username = session['username']
        session.clear()
        flash(f'Вы вышли из системы, {username}', 'info')
    else:
        session.clear()
        flash('Вы вышли из системы', 'info')
    
    return redirect(url_for('index'))

@app.route('/ping')
def ping():
    """Эндпоинт для пинга, чтобы сервис не засыпал"""
    return 'pong', 200

def init_database():
    """Инициализация базы данных и создание тестовых пользователей"""
    with app.app_context():
        # Создаем таблицы
        db.create_all()
        
        # Проверяем и создаем тестовых пользователей
        test_users = [
            {
                'username': 'admin',
                'password': 'admin123',
                'role': 'Администратор',
                'email': 'admin@example.com'
            },
            {
                'username': 'moderator',
                'password': 'moderator123',
                'role': 'Модератор',
                'email': 'moderator@example.com'
            },
            {
                'username': 'user',
                'password': 'user123',
                'role': 'Пользователь',
                'email': 'user@example.com'
            },
            {
                'username': 'guest',
                'password': 'guest123',
                'role': 'Гость',
                'email': 'guest@example.com'
            }
        ]
        
        for user_data in test_users:
            if not User.query.filter_by(username=user_data['username']).first():
                user = User(
                    username=user_data['username'],
                    role=user_data['role'],
                    email=user_data['email']
                )
                user.set_password(user_data['password'])
                db.session.add(user)
                print(f"✅ Создан пользователь: {user_data['username']} ({user_data['role']})")
        
        db.session.commit()
        print("✅ База данных инициализирована успешно!")

# Инициализация базы данных при запуске
init_database()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)