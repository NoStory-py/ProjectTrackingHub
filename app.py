import matplotlib, os, pdfkit, secrets, re, textwrap, base64, warnings
import matplotlib.pyplot as plt
from flask import Flask, render_template, redirect, url_for, request, session, flash, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Todo, TodoBlock, Project, user_project_association
from flask_oauthlib.client import OAuth
from flask_wtf import FlaskForm
from wtforms import SubmitField
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from pytz import timezone, utc
from sqlalchemy import text, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from itsdangerous import URLSafeSerializer, BadSignature
from flask_migrate import Migrate
from io import BytesIO
import os
#----------------------------------------------------------------------------------------------------------------------------------------------------

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY')

# Mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') 
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
db.init_app(app)
migrate = Migrate(app, db)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

warnings.filterwarnings('ignore')
# Index page---------------------------------------------------------------------------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('login.html')

# authorization-----------------------------------------------------------------------------------------------------------------------------------------------
SIGNUP_TOKEN_EXP = 24
PASSWORD_TOKEN_EXP = 1

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        username = request.form.get('username')
        moodle = request.form.get('moodle')

        if not is_valid_password(password):
            flash("Password must contain: at least one letter, one number, one special character and be at least 8 characters long", "auth")
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash("User already exists!!!", "auth")
        elif "@" in email and "." in email:
            if password == password2:
                hashed_password = generate_password_hash(password)
                new_user = User(email=email, password=hashed_password, username = username, moodle = moodle)
            
                db.session.add(new_user)
                db.session.commit()
                flash("Registration Completed Successfully", "auth")
                return redirect(url_for('login'))
            else:
                flash("Passwords don't match", "auth")
        else:
            flash("Invalid Email address", "auth")

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('projects'))
        else:
            flash("Invalid email address or password", 'auth')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        user = User.query.filter_by(email=email).first()
        if user:
            
           
            token_data = {'email': email, 'used': False}
            serializer = URLSafeSerializer(app.config['SECRET_KEY'])
            reset_token = serializer.dumps(token_data)
            send_password_reset_email(email = email, token =reset_token)
        else:
            flash('User with the provided email does not exist.', 'auth')

    return render_template('forgot_password.html')

def send_password_reset_email(email, token):
    msg = Message('Password Reset Request', recipients=[email])
    msg.body = f'Click the following link to reset your password: http://localhost:5000/reset_password/{token}'

    try:
        mail.send(msg)
        flash("Password reset email sent successfully.", "auth")
    except Exception as e:
        flash(f"Failed to send password reset email to {email}: {e}", "auth")

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['password']
        new_password2 = request.form['password2']

        serializer = URLSafeSerializer(app.config['SECRET_KEY'])
        try:
            token_data = serializer.loads(token)
            email = token_data['email']
            token_used = token_data.get('used', False)

        except BadSignature:
            flash('Invalid or expired token. Please request a new password reset link.', 'auth')
            return redirect(url_for('forgot_password'))

        if token_used:
            flash('This password reset link has already been used.', 'auth')
            return redirect(url_for('forgot_password'))
        
        if not is_valid_password(new_password):
            flash("Password must contain: at least one letter, one number, one special character and be at least 8 characters long", "auth")
        else:
            if new_password == new_password2:
                user = User.query.filter_by(email=email).first()
                if user:
                    user.password = generate_password_hash(new_password)
                    db.session.commit()

                    token_data['used'] = True

                    return redirect(url_for('login'))
                else:
                    flash('User not found', 'error')
                    return redirect(url_for('forgot_password'))
            else:
                flash("Passwords dont match!","auth")
    return render_template('reset_password.html', token = token)

# Project dashboard-------------------------------------------------------------------------------------------------------------------------------------------

# retrieve all the projects that a user has
@app.route('/projects')
@login_required
def projects():
    user_projects = get_user_projects(current_user.id)
    return render_template('projects.html', projects=user_projects)

class ProjectReportForm(FlaskForm):
    submit = SubmitField('Project Report')

# retrieving details of a particular project
@app.route('/project/<int:project_id>')
def project_details(project_id):

    project = get_project_or_none(project_id)
    if not project:
        flash('Project not found', 'error')
        return redirect(url_for('projects'))

    #todo_blocks = project.todo_blocks
    todo_blocks = TodoBlock.query.filter_by(project_id=project.id).order_by(TodoBlock.id.asc()).all()
    for todo_block in todo_blocks:
        todo_block.todos = sorted(todo_block.todos, key=lambda x: x.id)

    form = ProjectReportForm()

    query = text("SELECT is_admin FROM user_project_association WHERE user_id = :user_id AND project_id = :project_id")
    result = db.session.execute(query, {"user_id": current_user.id, "project_id": project_id})
    admin_association = result.fetchone()

    return render_template('task.html', project=project, todo_blocks=todo_blocks, form = form, admin_association = admin_association)

@app.route('/create_project', methods=['POST'])
@login_required
def create_project():
    project_name = request.form.get('name')
    default_template = request.form.get('default_template')
    project_desc = request.form.get('Description')

    if project_name:
        if default_template == "true":
            if project_desc:
                    return redirect(url_for('default_template', project_name=project_name, project_desc=project_desc))
            else:
                project_desc = "Default Description" 
                return redirect(url_for('default_template', project_name=project_name, project_desc=project_desc))
        else:
            new_project = Project(name=project_name, description = project_desc)
            current_user.projects.append(new_project)  
            db.session.add(new_project)
            db.session.commit()

            query = text("UPDATE user_project_association SET is_admin = :is_admin WHERE user_id = :user_id AND project_id = :project_id")
            db.session.execute(query, {"user_id": current_user.id, "project_id": new_project.id, "is_admin": True})

            db.session.commit()
        

        return redirect(url_for('project_details', project_id=new_project.id))
    else:

        return redirect(url_for('projects'))

@app.route('/default_template/<project_name>/<project_desc>', methods=['GET', 'POST'])
@login_required
def default_template(project_name, project_desc):
    if project_name:
        new_project = Project(name=project_name, description = project_desc)
        current_user.projects.append(new_project)  
        db.session.add(new_project)

        todo_block_1 = TodoBlock(name='Literature Survey', project=new_project)
        todo_block_2 = TodoBlock(name='Problem Statement', project=new_project)
        todo_block_3 = TodoBlock(name='Objectives & Scope', project=new_project)
        todo_block_4 = TodoBlock(name='Design', project=new_project)
        todo_block_5 = TodoBlock(name='Implementation', project=new_project)
        todo_block_6 = TodoBlock(name='Testing', project=new_project)
        todo_block_7 = TodoBlock(name='Deployment', project=new_project)
        todo_block_8 = TodoBlock(name='Maintainance', project=new_project)
        print("done")
        
        
        db.session.add_all([todo_block_1, todo_block_2, todo_block_3, todo_block_4, todo_block_5, todo_block_6, todo_block_7, todo_block_8])
        db.session.commit()

        query = text("UPDATE user_project_association SET is_admin = :is_admin WHERE user_id = :user_id AND project_id = :project_id")
        db.session.execute(query, {"user_id": current_user.id, "project_id": new_project.id, "is_admin": True})

        db.session.commit()

        flash('Project created successfully', 'success')
        return redirect(url_for('project_details', project_id=new_project.id))
    else:
        flash('Failed to create default template', 'error')
        return redirect(url_for('projects'))

@app.route('/delete_project/<int:project_id>', methods=['POST', 'GET'])
@login_required
def delete_project(project_id):
    project = Project.query.get(project_id)
    if project:
        query = text("SELECT is_admin FROM user_project_association WHERE user_id = :user_id AND project_id = :project_id")
        result = db.session.execute(query, {"user_id": current_user.id, "project_id": project_id})
        admin_association = result.fetchone()
        if current_user in project.users:
            if admin_association and admin_association[0]:
                try:
                    todo_blocks = TodoBlock.query.filter_by(project_id=project_id).all()
                    if todo_blocks:
                        for block in todo_blocks:
                            todos = Todo.query.filter_by(todo_block_id=block.id).all()
                            if todos:
                                for todo in todos:
                                    db.session.delete(todo)
                            db.session.delete(block)

                    db.session.query(user_project_association).filter_by(project_id=project_id).delete()

                    db.session.delete(project)
                    db.session.commit()
                    return redirect(url_for('projects'))
                except Exception as e:
                    print(e)
                except IntegrityError as ie:
                    db.session.rollback()
                    print(ie)
    return redirect(url_for('project_details', project_id = project_id))

# Todo-Blocks, TaskList create, update, delete operations-----------------------------------------------------------------------------------------------------------------------------

@app.route('/add_block', methods=['POST'])
@login_required
def add_block():
    name = request.form.get('name')
    project_id = request.form.get('project_id')
    if name and project_id:
        new_block = create_todo_block(name, project_id)
    return redirect(url_for('project_details', project_id=project_id))

@app.route('/delete_block/<int:project_id>/<int:block_id>', methods=['POST', 'DELETE'])
@login_required
def delete_block(project_id, block_id):
    block_deleted = delete_todo_block(project_id, block_id)
    return redirect(url_for('project_details', project_id=project_id))

@app.route('/edit_block/<int:project_id>/<int:block_id>', methods=['POST'])
@login_required
def edit_block(project_id, block_id):
    name = request.form['block_name']
    block = TodoBlock.query.get(block_id)
    block.name = name
    db.session.commit()
    return redirect(url_for('project_details', project_id = project_id))

# Task create update delete operations-----------------------------------------------------------------------------------------------------------------------------------

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    content = request.form.get('content')
    todo_block_id = request.form.get('todo_block_id')
    due_date_str = request.form.get('due_date')  # Get due date string from form
    due_date = datetime.strptime(due_date_str, '%Y-%m-%dT%H:%M') if due_date_str else None  # Parse due date if provided

    user_id=current_user.id

    if content and todo_block_id:
        task_added = add_todo_task(content, todo_block_id, due_date, user_id)
    return redirect(url_for('project_details', project_id=get_project_id_from_block(todo_block_id)))

@app.route('/delete_task/<int:todo_id>', methods=['DELETE', 'POST'])
@login_required
def delete_task(todo_id):
    print(todo_id)
    task = Todo.query.get(todo_id)
    project_id = task.todo_block.project_id if task else None

    task_deleted = delete_todo_task(todo_id)

    if project_id:
        return redirect(url_for('project_details', project_id=project_id))
    else:

        return redirect(url_for('projects'))

@app.route('/checkbox/<int:todo_id>', methods=['POST'])
@login_required
def checkbox(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    todo.completed = not todo.completed

    if todo.completed:
        if todo.due_date and todo.completed:
            due_date_utc = todo.due_date.replace(tzinfo=utc)
            current_time_utc = datetime.now(utc)
            print(current_time_utc, "-------",due_date_utc )
            print(current_time_utc <= due_date_utc)
            if current_time_utc <= due_date_utc:
                todo.completed_before_due = True
            else:
                todo.completed_before_due = False

    db.session.commit()
    return redirect(url_for('project_details', project_id=todo.todo_block.project_id))

@app.route('/edit_task/<int:todo_id>', methods=['POST'])
@login_required
def edit_task(todo_id):
    content = request.form['content']
    due_date_str = request.form['due_date']
    
    due_date = datetime.strptime(due_date_str, '%Y-%m-%dT%H:%M') if due_date_str else None 

    todo = Todo.query.get(todo_id)
    
    todo.content = content
    todo.due_date = due_date
    
    db.session.commit()
    
    return redirect(url_for('project_details', project_id = todo.todo_block.project_id))

# functions created to avoid repeating of code--------------------------------------------------------------------------------------------------------------------------------------

def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[a-zA-Z]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def get_user_projects(user_id):
    user = User.query.get(user_id)
    if user:
        return user.projects
    return []

def get_project_or_none(project_id):
    return Project.query.get(project_id)

def create_project_for_user(project_name, user_id):
    new_project = Project(name=project_name, user_id=user_id)
    db.session.add(new_project)
    db.session.commit()
    print(type(new_project))
    return new_project

def create_todo_block(name, project_id):
    new_block = TodoBlock(name=name, project_id=project_id)
    db.session.add(new_block)
    db.session.commit()
    return new_block

def delete_todo_block(project_id, block_id):
    block = TodoBlock.query.filter_by(id=block_id, project_id=project_id).first()
    Todo.query.filter_by(todo_block_id=block_id).delete()
    db.session.commit()

    if block:
        db.session.delete(block)
        db.session.commit()
        return True
    return Falses

def add_todo_task(content, todo_block_id, due_date, user_id):
    new_task = Todo(content=content, todo_block_id=todo_block_id, due_date = due_date, user_id = user_id)
    db.session.add(new_task)
    db.session.commit()
    return True

def delete_todo_task(todo_id):
    task = Todo.query.get(todo_id)
    if task:
        db.session.delete(task)
        db.session.commit()
        return True
    return False

def get_project_id_from_block(todo_block_id):
    block = TodoBlock.query.get(todo_block_id)
    return block.project_id if block else None

# user management-------------------------------------------------------------------------------------------------------------------------------------------

@app.route('/add_user_to_project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def add_user_to_project(project_id):
    email = request.form.get('email')
    add_as = request.form.get('add_as')
    add_with = request.form.get('add_with')
    print(add_as,add_with)
    if add_with == "Email":
        user_to_add = User.query.filter_by(email=email).first()
    elif add_with == "Moodle":
        user_to_add = User.query.filter_by(moodle=email).first()

    query = text("SELECT is_admin FROM user_project_association WHERE user_id = :user_id AND project_id = :project_id")
    result = db.session.execute(query, {"user_id": current_user.id, "project_id": project_id})
    admin_association = result.fetchone()

    if admin_association and admin_association[0]:
        if not user_to_add:
            flash('User with the provided email does not exist', 'user')
        else:
            project = Project.query.get(project_id)
            if project:
                # Check if the user to add is already associated with the project
                if user_to_add in project.users:
                    flash('User is already part of the project', 'user')
                else:
                    # Add the user to the project
                    project.users.append(user_to_add)
                    db.session.commit()
                    
                    if add_as == "Admin":
                        query = text("UPDATE user_project_association SET is_admin = :is_admin WHERE user_id = :user_id AND project_id = :project_id")
                        db.session.execute(query, {"user_id": user_to_add.id, "project_id": project_id, "is_admin": True})
                        db.session.commit()
                        flash("User added as an Admin successfully",'user')
                    else:
                        flash("User added as a Member successfully",'user')

            else:
                flash('Project not found', 'user')

    return redirect(url_for('project_details', project_id=project_id))

@app.route('/remove_user/<int:project_id>', methods=['GET', 'POST'])
@login_required
def remove_user(project_id):
    email = request.form.get('email')
    remove_with = request.form.get('remove_with')
    
    if remove_with == "Email":
        user_to_remove = User.query.filter_by(email=email).first()
    elif remove_with == "Moodle":
        user_to_remove = User.query.filter_by(moodle=email).first()

    query = text("SELECT is_admin FROM user_project_association WHERE user_id = :user_id AND project_id = :project_id")
    result = db.session.execute(query, {"user_id": current_user.id, "project_id": project_id})
    admin_association = result.fetchone()

    if admin_association and admin_association[0]:
        if not user_to_remove:
            flash('User with the provided email does not exist', 'user')
            return redirect(url_for('project_details', project_id=project_id))
        project = Project.query.get(project_id)
        if user_to_remove in project.users:
            project.users.remove(user_to_remove)
            db.session.commit()
            
            # Find todo blocks associated with the project and delete todos from those blocks
            todo_blocks = TodoBlock.query.filter_by(project_id=project_id).all()
            for todo_block in todo_blocks:
                todos_to_delete = Todo.query.filter_by(user_id=user_to_remove.id, todo_block_id=todo_block.id).all()
                for todo in todos_to_delete:
                    db.session.delete(todo)
            db.session.commit()

            flash('User removed from the project, and associated todos deleted', 'user')
        else:
            flash('User is not part of the project', 'user')
    else:
        flash('You do not have permission to remove users from this project', 'user')

    return redirect(url_for('project_details', project_id=project_id))

# project report-------------------------------------------------------------------------------------------------------------------------------------

@app.route('/generate_report/<int:project_id>', methods=['GET', 'POST'])
def generate_report(project_id):
    # Fetch data for the project based on project_id
    project = Project.query.get(project_id)
    form = ProjectReportForm()
    todo_blocks = project.todo_blocks
    users = project.users
    project_name = project.name

    # Define function to calculate progress
    def calculate_progress(todo_block):
        total_tasks = len(todo_block.todos)
        completed_tasks = sum(1 for todo in todo_block.todos if todo.completed)
        progress = 0
        if total_tasks > 0:
            progress = round((completed_tasks / total_tasks) * 100)
        return f"Progress: {progress}% ({completed_tasks}/{total_tasks} completed)"

    def overall_progress(todo_block):
        total_tasks = sum(len(todo_block.todos) for todo_block in todo_blocks)
        completed_tasks = sum(sum(1 for todo in todo_block.todos if todo.completed) for todo_block in todo_blocks)
        overall_progress = 0
        if total_tasks > 0:
            overall_progress = round((completed_tasks / total_tasks) * 100)
        return f"Overall Progress: {overall_progress}% ({completed_tasks}/{total_tasks} completed)"

    def user_progress(user, project):
        # Filter todos based on the project
        project_todos = [todo for todo in user.todos if todo.todo_block.project_id == project.id]
        total_tasks = len(project_todos)
        completed_tasks = sum(1 for todo in project_todos if todo.completed)
        total_progress = 0
        if total_tasks > 0:
            total_progress = round((completed_tasks / total_tasks) * 100)
        return f"Progress: {total_progress}% ({completed_tasks}/{total_tasks} completed)"

    # Calculate overall progress data
    overall_total_tasks = sum(len(todo_block.todos) for todo_block in todo_blocks)
    overall_completed_tasks = sum(sum(1 for todo in todo_block.todos if todo.completed) for todo_block in todo_blocks)
    overall_progress_data = [(sum(1 for todo in todo_block.todos if todo.completed) / len(todo_block.todos)) * 100 
                         if len(todo_block.todos) > 0 else 0 for todo_block in todo_blocks]
    overall_labels = [textwrap.fill(todo_block.name, width=10) for todo_block in todo_blocks]
    overall_colors = ['lightcoral', 'lightskyblue', 'lightgreen', 'gold']

    # Create bar chart for overall progress
    plt.figure(figsize=(8, 6))
    bars = plt.bar(overall_labels, overall_progress_data, color=overall_colors)
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, yval + 1, f"{round(yval, 1)}%", ha='center', va='bottom')

    plt.ylabel('Percentage Completed (%)')
    plt.ylim(0, 110)

    # Save overall chart to BytesIO buffer
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    plt.close()
    overall_chart_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    buffer.close()
    overall_chart_path = "overall_progress_chart.png"

    # Calculate user progress data
    user_progress_data = [(sum(1 for todo in user.todos if todo.todo_block.project_id == project.id and todo.completed) /
                        len([todo for todo in user.todos if todo.todo_block.project_id == project.id]) * 100)
                        if len([todo for todo in user.todos if todo.todo_block.project_id == project.id]) > 0 else 0
                        for user in users]
    user_labels = [user.username for user in users]
    user_colors = ['lightcoral', 'lightskyblue', 'lightgreen', 'gold']

    # Create bar chart for user progress
    plt.figure(figsize=(8, 5))
    bars = plt.bar(user_labels, user_progress_data, color=user_colors)
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, yval + 1, f"{round(yval, 1)}%", ha='center', va='bottom')

    plt.xlabel('Users')
    plt.ylabel('Percentage Completed (%)')
    plt.ylim(0, 110)

    # Save user chart to BytesIO buffer
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    plt.close()
    user_chart_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    buffer.close()
    user_chart_path = "user_progress_chart.png"
    

    rendered_template = render_template('report.html', project=project, form=form, todo_blocks=todo_blocks, calculate_progress=calculate_progress, overall_progress = overall_progress, user_progress = user_progress, users = users, overall_chart_data=overall_chart_data, user_chart_data=user_chart_data)

    pdf = pdfkit.from_string(rendered_template, False)

    # Create a response with PDF as attachment
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename= {project_name}_Project_Report.pdf'

    return response

# this Ensure that the script is ran only when ran directly and not when you import it as a package----------------------------------------------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
    