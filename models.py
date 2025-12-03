from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# Определение разрешений (пермишенов)
class Permission:
    VIEW_DASHBOARD = 1
    EDIT_OWN_PROFILE = 2
    VIEW_ALL_USERS = 4
    EDIT_USERS = 8
    DELETE_USERS = 16
    VIEW_LOGS = 32
    MANAGE_SYSTEM = 64

# Определение ролей и их разрешений
class Role:
    ROLES = {
        'Гость': 0,
        'Пользователь': Permission.VIEW_DASHBOARD | Permission.EDIT_OWN_PROFILE,
        'Модератор': Permission.VIEW_DASHBOARD | Permission.EDIT_OWN_PROFILE | 
                    Permission.VIEW_ALL_USERS | Permission.EDIT_USERS | Permission.VIEW_LOGS,
        'Администратор': Permission.VIEW_DASHBOARD | Permission.EDIT_OWN_PROFILE |
                        Permission.VIEW_ALL_USERS | Permission.EDIT_USERS | 
                        Permission.DELETE_USERS | Permission.VIEW_LOGS | 
                        Permission.MANAGE_SYSTEM
    }

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Пользователь')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_permission(self, permission):
        """Проверяет, есть ли у пользователя указанное разрешение"""
        role_permissions = Role.ROLES.get(self.role, 0)
        return (role_permissions & permission) == permission
    
    def can(self, permission):
        """Альтернативный метод для проверки разрешений"""
        return self.has_permission(permission)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    ip_address = db.Column(db.String(45))
    
    user = db.relationship('User', backref=db.backref('logs', lazy=True))