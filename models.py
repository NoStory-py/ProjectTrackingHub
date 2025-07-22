from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import backref
from sqlalchemy import text


db = SQLAlchemy()

# user table model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    projects = db.relationship('Project', secondary='user_project_association', backref='user_projects', lazy='dynamic', overlaps="projects,user_projects")
    todos = db.relationship('Todo', backref='user', lazy=True)
    moodle = db.Column(db.String(100), nullable=True)
    username =  db.Column(db.String(100), nullable=False)

# project table model
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    users = db.relationship('User', secondary='user_project_association', backref='project_users', lazy='dynamic')
    todo_blocks = db.relationship('TodoBlock', backref='project', lazy=True)

# Define association table for many-to-many relationship between users and projects
user_project_association = db.Table(
    'user_project_association',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True),
    db.Column('is_admin', db.Boolean, nullable=False, default=False))

# todo_block table model
class TodoBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    todos = db.relationship('Todo', backref='todo_block', lazy=True)

# todo table model
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    todo_block_id = db.Column(db.Integer, db.ForeignKey('todo_block.id'), nullable=False)
    due_date = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    last_reminder_sent = db.Column(db.DateTime)  
    completed_before_due = db.Column(db.Boolean)

