from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, AuditLog, Role, Permission
from functools import wraps
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Декоратор для проверки разрешений
from functools import wraps

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.has_permission(permission):
                flash('У вас недостаточно прав для доступа к этой странице', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Декоратор для проверки роли
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.role != role_name:
                flash(f'Требуется роль {role_name}', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            
            # Логируем вход
            log = AuditLog(
                user_id=user.id,
                action=f'Пользователь {user.username} вошел в систему',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Логируем выход
    log = AuditLog(
        user_id=current_user.id,
        action=f'Пользователь {current_user.username} вышел из системы',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
@permission_required(Permission.VIEW_DASHBOARD)
def dashboard():
    """Панель управления - доступна всем авторизованным пользователям с соответствующим разрешением"""
    return render_template('user.html')

@app.route('/admin')
@login_required
@role_required('Администратор')
def admin_panel():
    """Панель администратора - только для администраторов"""
    users = User.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return render_template('admin.html', users=users, logs=logs)

@app.route('/moderator')
@login_required
@permission_required(Permission.VIEW_ALL_USERS)
def moderator_panel():
    """Панель модератора - для модераторов и администраторов"""
    users = User.query.all()
    return render_template('moderator.html', users=users)

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@permission_required(Permission.DELETE_USERS)
def delete_user(user_id):
    """API для удаления пользователя - только для администраторов"""
    if current_user.id == user_id:
        return jsonify({'error': 'Нельзя удалить самого себя'}), 400
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    log = AuditLog(
        user_id=current_user.id,
        action=f'Пользователь {current_user.username} удалил пользователя {user.username}',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
@login_required
@permission_required(Permission.EDIT_USERS)
def change_user_role(user_id):
    """API для изменения роли пользователя"""
    user = User.query.get_or_404(user_id)
    new_role = request.json.get('role')
    
    if new_role not in Role.ROLES.keys():
        return jsonify({'error': 'Неверная роль'}), 400
    
    old_role = user.role
    user.role = new_role
    db.session.commit()
    
    log = AuditLog(
        user_id=current_user.id,
        action=f'Пользователь {current_user.username} изменил роль пользователя {user.username} с {old_role} на {new_role}',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'success': True})

# Инициализация базы данных и создание тестовых пользователей
def init_db():
    with app.app_context():
        db.create_all()
        
        # Создаем тестовых пользователей, если их нет
        if not User.query.first():
            # Администратор
            admin = User(username='admin', email='admin@example.com', role='Администратор')
            admin.set_password('admin123')
            
            # Модератор
            moderator = User(username='moderator', email='moderator@example.com', role='Модератор')
            moderator.set_password('moderator123')
            
            # Обычный пользователь
            user = User(username='user', email='user@example.com', role='Пользователь')
            user.set_password('user123')
            
            # Гость (не активирован)
            guest = User(username='guest', email='guest@example.com', role='Гость')
            guest.set_password('guest123')
            
            db.session.add_all([admin, moderator, user, guest])
            db.session.commit()
            
            print("Тестовые пользователи созданы:")
            print("1. admin / admin123 (Администратор)")
            print("2. moderator / moderator123 (Модератор)")
            print("3. user / user123 (Пользователь)")
            print("4. guest / guest123 (Гость)")

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)