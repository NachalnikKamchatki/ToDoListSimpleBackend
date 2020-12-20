from functools import wraps
import datetime

from flask import jsonify, make_response, request, abort, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

from app import app, db
from models import Task, User


def make_public_task(task):
    new_task = {}
    for field in task:
        if field == 'id':
            new_task['uri'] = url_for('get_task', task_id=task['id'], _external=True)
        else:
            new_task[field] = task[field]
    return new_task


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter(User.id == data['id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/todo/api/v1.0/register', methods=['POST'])
def signup_user():
    data = request.get_json()
    print(data)
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(
        name=data['name'],
        password=hashed_password, admin=False
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registered successfully'})


@app.route('/todo/api/v1.0/login', methods=['GET', 'POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response(
            'could not verify',
            401,
            {'WWW.Authentication': 'Basic realm: "login required"'}
        )
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response(
            'could not verify',
            401,
            {'WWW.Authentication': 'Basic realm: "login required"'}
        )

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response(
        'could not verify',
        401,
        {'WWW.Authentication': 'Basic realm: "login required"'}
    )


@app.route('/todo/api/v1.0/users', methods=['GET'])
def get_users():
    users = User.query.all()
    res = []
    for user in users:
        res.append({'id': user.id, 'name': user.name, 'password': user.password})
    return make_response(jsonify({"users": res}), 200)


@app.route('/todo/api/v1.0/tasks', methods=['GET'])
@token_required
def get_tasks(current_user):
    tasks = Task.query.filter(current_user.id == Task.user_id).all()
    res = []
    for task in tasks:
        res.append({'id': task.id, 'title': task.title, 'description': task.description, 'done': task.done})
    return make_response(jsonify({"tasks": list(map(make_public_task, res))}), 200)


@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['GET'])
@token_required
def get_task(current_user, task_id):
    task = Task.query.filter(Task.id == task_id, Task.user_id == current_user.id).first_or_404()
    return make_response(
        jsonify(make_public_task({
            'id': task.id,
            'title': task.title,
            'description': task.description,
            'done': task.done
        })),
        200
    )


@app.route('/todo/api/v1.0/tasks', methods=['POST'])
@token_required
def create_task(current_user):
    if not request.json or 'title' not in request.json:
        abort(400)
    task = Task(
        title=request.json['title'],
        description=request.json.get('description', None),
        user_id=current_user.id
    )
    db.session.add(task)
    db.session.commit()
    return make_response(jsonify({'status': 'success'}), 201)


@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(current_user, task_id):

    task = Task.query.filter(
        Task.id == task_id,
        Task.user_id == current_user.id
    ).first_or_404()

    if not request.json:
        abort(400)

    title = request.json.get('title', None)
    description = request.json.get('description', None)
    done = request.json.get('done', False)
    task.title = title if title else task.title
    task.description = description if description else task.description
    task.done = done
    db.session.add(task)
    db.session.commit()

    return make_response(jsonify({'status': 'success'}), 202)


@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
    task = Task.query.filter(
        Task.id == task_id,
        Task.user_id == current_user.id
    ).first_or_404()

    db.session.delete(task)
    db.session.commit()

    return make_response(jsonify({'status': 'success'}), 200)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found.'}), 404)


@app.errorhandler(400)
def not_found(error):
    return make_response(jsonify({'error': 'Bad request.'}), 404)
