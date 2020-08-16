from app import db

from passlib.hash import pbkdf2_sha256 as sha256


class UserModel(db.Model):
    """
    User Model Class
    """

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(120), unique=True, nullable=False)

    password = db.Column(db.String(120), nullable=False)

    """
    Save user details in Database
    """
    def save_to_db(self):

        db.session.add(self)

        db.session.commit()

    """
    Find user by username
    """
    @classmethod
    def find_by_username(cls, username):
        
        return cls.query.filter_by(username=username).first()

    """
    return all the user data in json form available in DB
    """
    @classmethod
    def return_all(cls):
        
        def to_json(x):
        
            return {
        
                'username': x.username,
        
                'password': x.password
        
            }
        
        return {'users': [to_json(user) for user in UserModel.query.all()]}

    """
    Delete user data
    """
    @classmethod
    def delete_all(cls):
        
        try:
        
            num_rows_deleted = db.session.query(cls).delete()
        
            db.session.commit()
        
            return {'message': f'{num_rows_deleted} row(s) deleted'}
        
        except:
        
            return {'message': 'Something went wrong'}

    """
    generate hash from password by encryption using sha256
    """
    @staticmethod
    def generate_hash(password):
        
        return sha256.hash(password)

    """
    Verify hash and password
    """
    @staticmethod
    def verify_hash(password, hash_):
        
        return sha256.verify(password, hash_)


class RevokedTokenModel(db.Model):
    """
    Revoked Token Model Class
    """

    __tablename__ = 'revoked_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    
    jti = db.Column(db.String(120))

    """
    Save Token in DB
    """
    def add(self):
    
        db.session.add(self)
    
        db.session.commit()

    """
    Checking that token is blacklisted
    """
    @classmethod
    def is_jti_blacklisted(cls, jti):
    
        query = cls.query.filter_by(jti=jti).first()
    
        return bool(query)