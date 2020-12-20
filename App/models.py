from app import db, app


class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text(500))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    done = db.Column(db.Boolean())
    # user = db.relationship('User', back_populates='tasks')

    def __init__(self, title, user_id, description=None, done=False):
        self.title = title
        self.description = description if description else 'Описание пока отсутствует'
        self.user_id = user_id
        self.done = done

    def __repr__(self):
        return f'<Task "{self.title}">'


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    password = db.Column(db.String(255), nullable=False)
    admin = db.Column(db.Boolean())

    def __repr__(self):
        return f'<User {self.name}>'
