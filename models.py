from app import app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum
from werkzeug.security import generate_password_hash
from datetime import date,datetime

'''
have to remake the data set there has been an edit also have to check serch tab for sponsors 
'''

db = SQLAlchemy(app)

class UserRole(db.Model):
    __tablename__ = 'user_role'
    role_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    role_name = db.Column(db.String(32), nullable=False)

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
    db.create_all()  # Creating database

    # Check and create roles
    roles = [
        {'role_name': 'admin'},
        {'role_name': 'sponsor'},
        {'role_name': 'influencer'}
    ]

    for role in roles:
        existing_role = UserRole.query.filter_by(role_name=role['role_name']).first()
        if not existing_role:
            new_role = UserRole(role_name=role['role_name'])
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

    # Fetching role objects
    sponsor_role = UserRole.query.filter_by(role_name='sponsor').first()
    influencer_role = UserRole.query.filter_by(role_name='influencer').first()

    # Check and insert sponsors if the table is empty
    if not Sponsor.query.first():
        sponsors_data = [
            {'username': 'sponsor1', 'email_id': 'sponsor1@example.com', 'password': 'password1', 'company_name': 'Company A', 'industry': 'Tech', 'bio': 'Tech company'},
            {'username': 'sponsor2', 'email_id': 'sponsor2@example.com', 'password': 'password2', 'company_name': 'Company B', 'industry': 'Finance', 'bio': 'Finance company'},
            {'username': 'sponsor3', 'email_id': 'sponsor3@example.com', 'password': 'password3', 'company_name': 'Company C', 'industry': 'Health', 'bio': 'Health company'},
            {'username': 'sponsor4', 'email_id': 'sponsor4@example.com', 'password': 'password4', 'company_name': 'Company D', 'industry': 'Retail', 'bio': 'Retail company'}
        ]

        for sponsor_data in sponsors_data:
            existing_user = User.query.filter_by(username=sponsor_data['username']).first()
            if not existing_user:
                user = User(
                    username=sponsor_data['username'],
                    email_id=sponsor_data['email_id'],
                    password=generate_password_hash(sponsor_data['password']),
                    role_id=sponsor_role.role_id
                )
                db.session.add(user)
                db.session.commit()
                sponsor = Sponsor(
                    id=user.id,
                    company_name=sponsor_data['company_name'],
                    industry=sponsor_data['industry'],
                    bio=sponsor_data['bio']
                )
                db.session.add(sponsor)
        db.session.commit()

    # Check and insert influencers if the table is empty
    if not InfluencerProfile.query.first():
        influencers_data = [
            {'username': 'influencer1', 'email_id': 'influencer1@example.com', 'password': 'password5', 'niche': 'Fashion', 'bio': 'Fashion influencer'},
            {'username': 'influencer2', 'email_id': 'influencer2@example.com', 'password': 'password6', 'niche': 'Fitness', 'bio': 'Fitness influencer'},
            {'username': 'influencer3', 'email_id': 'influencer3@example.com', 'password': 'password7', 'niche': 'Travel', 'bio': 'Travel influencer'},
            {'username': 'influencer4', 'email_id': 'influencer4@example.com', 'password': 'password8', 'niche': 'Food', 'bio': 'Food influencer'}
        ]

        for influencer_data in influencers_data:
            existing_user = User.query.filter_by(username=influencer_data['username']).first()
            if not existing_user:
                user = User(
                    username=influencer_data['username'],
                    email_id=influencer_data['email_id'],
                    password=generate_password_hash(influencer_data['password']),
                    role_id=influencer_role.role_id
                )
                db.session.add(user)
                db.session.commit()
                influencer_profile = InfluencerProfile(
                    id=user.id,
                    niche=influencer_data['niche'],
                    bio=influencer_data['bio']
                )
                db.session.add(influencer_profile)
        db.session.commit()

    # Check and insert campaigns if the table is empty
    if not Campaign.query.first():
        # Fetch existing sponsors
        sponsors = Sponsor.query.all()

        # Example campaigns with defined niches
        campaign_data = [
            ("Fashion Trendsetters", "Explore the latest in fashion", "Fashion"),
            ("Fitness for All", "Join our fitness movement", "Fitness"),
            ("Travel the World", "Discover amazing travel destinations", "Travel"),
            ("Gourmet Delights", "Taste the finest foods", "Food"),
            ("Beauty and You", "Enhance your beauty routine", "Beauty"),
            ("Tech Innovators", "Explore the latest in technology", "Technology"),
        ]

        for sponsor in sponsors:
            for campaign_name, description, niche in campaign_data:
                campaign_name_with_sponsor = f"{campaign_name} by {sponsor.company_name}"
                campaign = Campaign(
                    sponsor_id=sponsor.sponsor_id,
                    name=campaign_name_with_sponsor,
                    description=description,
                    start_date=datetime.now(),
                    end_date=datetime.now(),
                    budget=10000.0,
                    visibility='public',
                    goals="Increase brand awareness",
                    niche=niche,
                    campaign_status='ongoing'
                )
                db.session.add(campaign)
        db.session.commit()