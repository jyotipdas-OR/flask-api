from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'verysecurekey'
app.config['SQLALCHEMY_DATABASE_URI']  = 'sqlite:////Users/jyot7937/personal/user_api/sample.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(124), nullable=False)
    admin = db.Column(db.Boolean, nullable=False)
    group_id = db.Column(db.Integer, ForeignKey("group.id"))


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))


def token_required(f):
    @wraps(f)
    def inner_function(*args,**kwars):
        if 'x-access-header' in request.headers:
            token = request.headers['x-access-header']
            try:
                data = jwt.decode(token,app.config['SECRET_KEY'])
                current_user = User.query.filter_by(id=data['id']).first()
            except:
                return jsonify({'message': 'token is not valid'}), 401
            return f(current_user,*args,**kwars)
        else:
            return jsonify({'message': 'token is not valid'}), 401
    return inner_function



@app.route('/users/', methods=['GET'])
@token_required
def all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'You needs to be admin to fetch the data'})
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'name': user.name,
        'password': user.password,
        'admin': user.admin,
        'group_id': user.group_id
    } for user in users])

@app.route('/users/<user_id>/')
@token_required
def single_user(current_user,user_id):
    if not current_user.admin:
        return jsonify({'message': 'You needs to be admin to fetch the data'})
    user_data= User.query.filter_by(id=user_id).first()
    if user_data:
        return jsonify({
            'name': user_data.name,
            'admin': user_data.admin,
            'group_id': user_data.group_id
        })
    return jsonify({'message': 'User not found'})

@app.route('/users/', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'You needs to be admin to fetch the data'})
    data = request.get_json()
    hashed_passwd = generate_password_hash(data['password'], method='sha256')
    new_user = User(name= data['name'],
                    password= hashed_passwd,
                    admin= data['admin'],
                    group_id=data['group'] if 'group' in data else None
                    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"data": "New user  created"})

@app.route('/users/<user_id>/', methods=['PUT'])
@token_required
def update_user(current_user,user_id):
    if not current_user.admin:
        return jsonify({'message': 'You needs to be admin to fetch the data'})
    data = request.get_json()
    user_data = User.query.filter_by(id=user_id).first()
    if user_data:
        User.query.filter_by(id=user_id).update(data)
        db.session.commit()
        return jsonify({'message': 'Updated the user data'})

    return jsonify({'message': 'User not found'})


@app.route('/users/<user_id>/', methods=['DELETE'])
@token_required
def delete_user(current_user,user_id):
    if not current_user.admin:
        return jsonify({'message': 'You needs to be admin to fetch the data'})
    user_data = User.query.filter_by(id=user_id).first()
    if user_data:
        db.session.delete(user_data)
        db.session.commit()
        return jsonify({'message': 'User deleted'})
    return jsonify({'message': 'User not found'})

@app.route('/groups/', methods=['POST'])
@token_required
def create_group(current_user):
    data = request.get_json()
    if 'name'in data:
        new_group = Group(name=data['name'])
        db.session.add(new_group)
        db.session.commit()
        return jsonify({'message': 'New group created'})
    return jsonify({'message': 'Please check the input data'})


@app.route('/groups/', methods=['GET'])
@token_required
def fetch_all_group(current_user):
    if not current_user.admin:
        return jsonify({'message': 'You needs to be admin to fetch the data'})
    all_groups = Group.query.all()
    user_group_detail = []
    for group_id in [x.id for x in all_groups]:
        users = []
        user_ids = User.query.filter_by(group_id=group_id).all()
        for ids in user_ids:
            users.append(ids.name)
        user_group_detail.append({
            'group_id': group_id,
            'users': users
        })

    return jsonify(user_group_detail)


@app.route('/groups/<group_id>/', methods=['GET'])
@token_required
def search_user_in_group(current_user, group_id):
    if int(group_id) == current_user.group_id:
        user = request.args.get('user')
        search_usr = User.query.filter_by(id=int(user),group_id=int(group_id)).first()
        if search_usr:
            return jsonify({'message': 'user found in the group'})
        return jsonify({'message': 'user or group are not matching'})
    return jsonify({'message': 'user is not belongs to the group'})

@app.route('/groups/<group_id>/', methods=['POST'])
@token_required
def add_user_to_group(current_user, group_id):
    if group_id != current_user.group_id:
        return jsonify({'message': 'user is not belongs to the group'})
    data = request.get_json()
    if 'user' in data:
        for user in data['user']:
            User.query.filter_by(id=user).update({'group_id':group_id})
            db.session.commit()

        return jsonify({'message': 'added the users to the group'})
    return jsonify({'message':'please check the input data'})

@app.route('/groups/<group_id>/', methods=['DELETE'])
@token_required
def delete_user_from_group(current_user, group_id):
    if group_id != current_user.group_id:
        return jsonify({'message': 'user is not belongs to the group'})

    user = request.args.get('user')
    search_usr = User.query.filter_by(id=int(user), group_id=int(group_id)).first()
    if search_usr:
        search_usr.update({'group_id': None})
        db.session.commit()
        return jsonify({'message': 'deleted the user from the group'})
    return jsonify({'message': 'user does not belongs to the group'})

@app.route('/login')
def login():
    auth = request.authorization
    if auth and auth.password and auth.username :
        user = User.query.filter_by(name=auth.username).first()
        if user:
            if check_password_hash(user.password,auth.password):
                token = jwt.encode({'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                                   app.config['SECRET_KEY'])
                return jsonify({'token': token.decode('UTF-8')})
            return make_response('Can not verify the user', 401, {'WWW-Authenticate': 'Basic realm="Login Reuired"'})
        return make_response('Can not verify the user', 401, {'WWW-Authenticate': 'Basic realm="Login Reuired"'})
    return make_response('Can not verify the user', 401, {'WWW-Authenticate': 'Basic realm="Login Reuired"'})


if __name__ == '__main__':
    app.run(host='0.0.0.0.', port=5001,debug=True)
