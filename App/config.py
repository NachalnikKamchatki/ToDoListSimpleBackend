
class Config:
    DEBUG = True
    SECRET_KEY = 'very-very-secret-key'

    # DB config
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://root:123@localhost:3306/todo_list'
    SQLALCHEMY_TRACK_MODIFICATIONS = True

    JSON_AS_ASCII = False