from app import app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum
from werkzeug.security import generate_password_hash

'''
have to remake the data set there has been an edit also have to check serch tab for sponsors 
'''

db = SQLAlchemy(app)

class UserRole(db.Model):
    __tablename__ = 'user_role'
    role_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    role_name = db.Column(db.String(32), nullable=False)
    permissions = db.Column(db.String(10), nullable=False)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    role_id = db.Column(db.Integer, db.ForeignKey('user_role.role_id'), nullable=False)
    username = db.Column(db.String(32), nullable=False, unique=True)
    email_id = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)
    is_flagged = db.Column(db.Boolean ,default=False)
    role = db.relationship('UserRole', backref=db.backref('users', lazy=True))

class Sponsor(db.Model):
    __tablename__ = 'sponsors'
    sponsor_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(64))
    industry = db.Column(db.String(32))
    budget = db.Column(db.Float(10, 2))
    bio = db.Column(db.String(256))
    user = db.relationship('User', backref=db.backref('sponsors', lazy=True))

class InfluencerProfile(db.Model):
    __tablename__ = 'influencer_profile'
    influencer_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(64), nullable=True)
    niche = db.Column(db.String(32))
    followers = db.Column(db.Integer)
    bio = db.Column(db.String(256))
    user = db.relationship('User', backref=db.backref('influencer_profiles', lazy=True))
    
class Campaign(db.Model):
    __tablename__ = 'campaign'
    campaign_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsors.sponsor_id'), nullable=False)
    name = db.Column(db.String(32),unique=True, nullable=False)
    description = db.Column(db.String(128))
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    budget = db.Column(db.Float(10, 2), nullable=False)
    visibility = db.Column(Enum('private', 'public', name='visibility_types'), default='public', nullable=False)
    goals = db.Column(db.String(128))
    niche = db.Column(db.String(32),nullable=False)
    campaign_status = db.Column(Enum('ongoing', 'flagged', 'deleted', 'completed' ,name='campaign_status_types'), default='ongoing', nullable=False)

    #relationship
    sponsor = db.relationship('Sponsor', backref=db.backref('campaigns', lazy=True))

class AdRequest(db.Model):
    __tablename__ = 'ad_request'
    ad_request_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.campaign_id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_for = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.Column(db.String(64))
    requirements = db.Column(db.String(128))
    payment_amount = db.Column(db.Float(10, 2))
    status = db.Column(Enum('ongoing', 'pending', 'flagged', 'deleted', 'completed', 'rejected' ,name='ad_request_status_types'), default='pending', nullable=False)

    campaign = db.relationship('Campaign', backref=db.backref('ad_requests', lazy=True))
    creator = db.relationship('User', foreign_keys=[created_by], backref=db.backref('created_ad_requests', lazy=True))
    recipient = db.relationship('User', foreign_keys=[created_for], backref=db.backref('received_ad_requests', lazy=True))

with app.app_context():
    db.create_all() #creating database
    
    roles = [
        {'role_name': 'admin', 'permissions': 'all'},
        {'role_name': 'sponsor', 'permissions': 'limited'},
        {'role_name': 'influencer', 'permissions': 'limited'}
    ]

    # Check and create roles
    for role in roles:
        existing_role = UserRole.query.filter_by(role_name=role['role_name']).first()
        if not existing_role:
            new_role = UserRole(role_name=role['role_name'], permissions=role['permissions'])
            db.session.add(new_role)
    db.session.commit()

    # Check and create admin user
    admin_role = UserRole.query.filter_by(role_name='admin').first()
    admin_user = User.query.filter_by(username='admin').first()
    
    if not admin_user:
        admin_user = User(
            username='admin',
            email_id='admin@example.com',
            password=generate_password_hash('adminpassword'), 
            role_id=admin_role.role_id
        )
        db.session.add(admin_user)
        db.session.commit()