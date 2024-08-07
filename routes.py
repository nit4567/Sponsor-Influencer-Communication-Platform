from flask import render_template,request,flash,redirect,url_for,session
from app import app
from models import User,Sponsor,InfluencerProfile, db,AdRequest,Campaign
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps
from datetime import datetime


@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username).first()

    if not user:
        flash('Username not found. Please check your login details and try again.', 'error')
        return redirect(url_for('login'))

    if not check_password_hash(user.password, password):
        flash('Incorrect password. Please check your login details and try again.', 'error')
        return redirect(url_for('login'))

    session['user_id']=user.id
    session['role_id']=user.role_id

    if user.is_flagged:
        flash('Your account is flagged and cannot perform this action.', 'error')
        return redirect(url_for('login'))
    
    if user.role_id == 1:
        return redirect(url_for('admin_dashboard', id=user.id))
    elif user.role_id == 3:
        return redirect(url_for('influencer_dashboard', id=user.id))
    elif user.role_id == 2:
        spon = Sponsor.query.filter_by(id=user.id).first()
        session['sponsor_id'] = spon.sponsor_id
        return redirect(url_for('sponsor_dashboard'))
    else:
        flash('Invalid user role.', 'error')
        return redirect(url_for('login'))
    
@app.route('/inf_register')
def inf_register():
    return render_template("inf_register.html")

@app.route('/inf_register', methods=['POST'])
def inf_register_post():
    username = request.form['username']
    name = request.form.get('name')
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    niche = request.form['niche']
    bio = request.form['bio']
    followers = request.form.get('followers')

    if not username or not email or not password or not confirm_password:
        flash('All fields are required!', 'error')
        return redirect(url_for('inf_register'))
    
    if password != confirm_password:
        flash('Passwords do not match!', 'error')
        return redirect(url_for('inf_register'))
    
    user = User.query.filter_by(username=username).first()
    if user:
        flash('Username already exists','error')
        return redirect(url_for('inf_register'))
    
    password_hash = generate_password_hash(password)

    new_user= User(role_id=3,username=username,password=password_hash,email_id=email)
    db.session.add(new_user)
    db.session.commit()
    
    new_inf = InfluencerProfile(id=new_user.id, name=name,niche=niche, bio=bio, followers= followers)
    db.session.add(new_inf)
    db.session.commit()

    flash('Successfully registered as an Influencer!', 'success')

    return redirect(url_for('login'))

@app.route('/spon_register')
def spon_register():
    return render_template("spon_register.html")

@app.route('/spon_register', methods=['POST'])
def spon_register_post():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    company_name = request.form['company_name']
    industry = request.form['industry']
    bio = request.form['bio']
    budget = request.form['budget']

    if not username or not email or not password or not confirm_password:
        flash('All fields are required!', 'error')
        return redirect(url_for('spon_register'))
    
    if password != confirm_password:
        flash('Passwords do not match!', 'error')
        return redirect(url_for('spon_register'))

    user = User.query.filter_by(username=username).first()
    if user:
        flash('Username already exists','error')
        return redirect(url_for('spon_register'))

    password_hash = generate_password_hash(password)

    new_user= User(role_id=2,username=username,password=password_hash,email_id=email)
    db.session.add(new_user)
    db.session.commit()
    
    new_spon = Sponsor(id=new_user.id,industry=industry,company_name=company_name, bio=bio, budget=budget)
    db.session.add(new_spon)
    db.session.commit()

    flash('Successfully registered as a Sponsor!', 'success')

    return redirect(url_for('login'))

# decorator for auth_req
def auth_rep(func):
    @wraps(func)
    def inner(*args,**kwargs):
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user.is_flagged:
                flash('Your account is flagged and cannot perform this action.', 'error')
                return redirect(url_for('login')) 
            return func(*args,**kwargs)
        
        else:
            flash('You are not logged in,Please login to proceed','error')
            return redirect(url_for('login'))
    return inner

def check_adr_editable(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        request_id = kwargs.get('request_id')
        ad_request = AdRequest.query.get(request_id)
        if not session.get('role_id')==1:
            if ad_request and ad_request.status in ['rejected', 'flagged', 'deleted']:
                flash('This Ad Request cannot be modified as it is either rejected or flagged.', 'error')
                if session.role_id==2:
                    return redirect(url_for('sponsor_dashboard'))  # Redirect to a suitable page
                elif session.role_id==3:
                    return redirect(url_for('influencer_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def check_campaign_editable(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        campaign_id = kwargs.get('campaign_id')
        campaign = Campaign.query.get(campaign_id)
        if campaign.campaign_status in ['completed', 'deleted','flagged']:
            flash('This campaign cannot be modified.', 'error')
            return redirect(url_for('sponsor_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role_id):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role_id') != role_id:
                flash('Access denied.', 'danger')
                redirect(request.referrer or url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@auth_rep
def index():
    return render_template('index.html')

@app.route('/influencer_dashboard')
@auth_rep
def influencer_dashboard():
    user_id = session.get('user_id')
    influencer = InfluencerProfile.query.filter_by(id=user_id).first()
    user = User.query.filter_by(id=user_id).first()

    # Get the list of campaign IDs for ad requests where the influencer is either the creator or recipient
    ad_request_campaign_ids = db.session.query(AdRequest.campaign_id).filter(
        (AdRequest.created_for == user_id) | (AdRequest.created_by == user_id)
    ).subquery()

    # Filter campaigns based on niche and only include those in the list of ad request campaign IDs
    active_campaigns = Campaign.query.filter(
        Campaign.campaign_id.in_(ad_request_campaign_ids),
        Campaign.niche == influencer.niche,
        Campaign.campaign_status == 'ongoing',
    ).all()

    new_requests = AdRequest.query.filter(
        (AdRequest.created_for == user_id) | (AdRequest.created_by == user_id)
    ).all()

    return render_template('dashboard_inf.html', user=user, influencer=influencer, active_campaigns=active_campaigns, new_requests=new_requests)


@app.route('/sponsor_dashboard')
@auth_rep
@role_required(2)
def sponsor_dashboard():
    user_id = session.get('user_id')
    user = User.query.filter_by(id=user_id).first()
    sponsor = Sponsor.query.filter_by(id=user_id).first_or_404()
    active_campaigns = Campaign.query.filter(Campaign.sponsor_id == sponsor.sponsor_id, 
                                             Campaign.campaign_status.in_(['ongoing', 'completed'])).all()
    new_requests = AdRequest.query.filter(AdRequest.created_for==user_id,AdRequest.status.in_(['ongoing', 'completed','pending'])).all()

    return render_template('dashboard_spon.html', sponsor=sponsor, active_campaigns=active_campaigns, new_requests=new_requests, user=user)


@app.route('/admin/dashboard')
@auth_rep
@role_required(1)
def admin_dashboard():
    flagged_campaigns = Campaign.query.filter_by(campaign_status='flagged').all()
    flagged_influencers = User.query.filter_by(is_flagged=True, role_id=3).all()
    flagged_sponsors = User.query.filter_by(is_flagged=True, role_id=2).all()
    
    return render_template('admin_dashboard.html', 
                           flagged_campaigns=flagged_campaigns, 
                           flagged_influencers=flagged_influencers,
                           flagged_sponsors=flagged_sponsors)

@app.route('/admin/search', methods=['GET'])
@auth_rep
@role_required(1)
def admin_search():
    return render_template('admin_search.html')


@app.route('/admin/flag_user/<int:user_id>', methods=['POST'])
@auth_rep
@role_required(1)
def flag_user(user_id):
    user = User.query.get(user_id)
    user.is_flagged = True
    db.session.commit()
    flash('User has been flagged.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/unflag_user/<int:user_id>', methods=['POST'])
@auth_rep
@role_required(1)
def unflag_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_flagged = False
    db.session.commit()
    flash('User has been unflagged.', 'success')
    return redirect(request.referrer)

@app.route('/admin/flag_campaign/<int:campaign_id>', methods=['POST'])
@auth_rep
@role_required(1)
def flag_campaign(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    campaign.campaign_status = 'flagged'
    db.session.commit()
    flash('Campaign has been flagged.', 'success')
    return redirect(request.referrer)

@app.route('/admin/unflag_campaign/<int:campaign_id>', methods=['POST'])
@auth_rep
@role_required(1)
def unflag_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    campaign.campaign_status = 'ongoing'  # or whatever the default status should be
    db.session.commit()
    flash('Campaign has been unflagged.', 'success')
    return redirect(request.referrer)

@app.route('/stats')
@auth_rep
def stats():
    # Active Users
    active_influencers = User.query.join(InfluencerProfile).filter(User.is_flagged == False, User.role_id == 3).count()
    active_sponsors = User.query.join(Sponsor).filter(User.is_flagged == False, User.role_id == 2).count()

    # Total Campaigns and Their Visibility
    total_campaigns = Campaign.query.count()
    public_campaigns = Campaign.query.filter(Campaign.visibility == 'public').count()
    private_campaigns = Campaign.query.filter(Campaign.visibility == 'private').count()

    # Campaigns by Status
    ongoing_campaigns = Campaign.query.filter(Campaign.campaign_status == 'ongoing').count()
    completed_campaigns = Campaign.query.filter(Campaign.campaign_status == 'completed').count()
    flagged_campaign = Campaign.query.filter(Campaign.campaign_status == 'flagged').count()
    deleted_campaigns = Campaign.query.filter(Campaign.campaign_status == 'deleted').count()

    # Total Ad Requests
    total_ad_requests = AdRequest.query.count()
    pending_ad_requests = AdRequest.query.filter(AdRequest.status == 'pending').count()
    approved_ad_requests = AdRequest.query.filter(AdRequest.status == 'approved').count()
    rejected_ad_requests = AdRequest.query.filter(AdRequest.status == 'rejected').count()

    # Flagged Users
    flagged_influencers = User.query.filter(User.is_flagged == True, User.role_id == 3).count()
    flagged_sponsors = User.query.filter(User.is_flagged == True, User.role_id == 2).count()

    # Campaigns per Niche
    niches = ['Fashion', 'Fitness', 'Travel', 'Food', 'Beauty', 'Technology', 'Lifestyle', 'Health', 'Music', 'Gaming', 'Art', 'Education', 'Finance']
    campaigns_per_niche = {niche: Campaign.query.filter(Campaign.niche == niche).count() for niche in niches}

    stats_data = {
        'active_influencers': active_influencers,
        'active_sponsors': active_sponsors,
        'total_campaigns': total_campaigns,
        'public_campaigns': public_campaigns,
        'private_campaigns': private_campaigns,
        'ongoing_campaigns': ongoing_campaigns,
        'completed_campaigns': completed_campaigns,
        'flagged_campaign': flagged_campaign,
        'deleted_campaigns': deleted_campaigns,
        'total_ad_requests': total_ad_requests,
        'pending_ad_requests': pending_ad_requests,
        'approved_ad_requests': approved_ad_requests,
        'rejected_ad_requests': rejected_ad_requests,
        'flagged_influencers': flagged_influencers,
        'flagged_sponsors': flagged_sponsors,
        'campaigns_per_niche': campaigns_per_niche
    }

    return render_template('stats.html', stats_data=stats_data)

@app.route('/campaign_details/<int:campaign_id>')
@auth_rep
def campaign_details(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    requests = AdRequest.query.filter_by(campaign_id=campaign_id)
    return render_template('campaign_details.html', campaign=campaign,requests=requests)

@app.route('/sponsor_dashboard/create_campaign', methods=['GET', 'POST'])
@auth_rep
def create_campaign():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        budget = request.form.get('budget')
        visibility = request.form.get('visibility')
        goals = request.form.get('goals')
        niche = request.form.get('niche')

        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.','error')
            return redirect(url_for('create_campaign', sponsor_id=session['sponsor_id']))
        
        # Check if a campaign with the same name already exists
        existing_campaign = Campaign.query.filter_by(name=name).first()
        if existing_campaign:
            flash('A campaign with this name already exists. Please choose a different name.', 'error')
            return redirect(url_for('create_campaign', sponsor_id=session['sponsor_id']))


        new_campaign = Campaign(
            sponsor_id=session['sponsor_id'],
            name=name,
            description=description,
            start_date=start_date,
            end_date=end_date,
            budget=budget,
            visibility=visibility,
            goals=goals,
            niche=niche
        )
        
        db.session.add(new_campaign)
        db.session.commit()

        flash('Campaign created successfully!','success')
        return redirect(url_for('sponsor_dashboard'))  
    return render_template('create_campaign.html')

@app.route('/campaign/<int:campaign_id>/update', methods=['GET','POST'])
@auth_rep
@check_campaign_editable
def update_campaign(campaign_id):
    user_id = session.get('user_id')
    role_id = session.get('role_id')

    if role_id != 2:  # Ensure only sponsors can access this page
        flash('You do not have permission to access this page','error')
        return redirect(url_for('index'))

    campaign = Campaign.query.filter_by(campaign_id=campaign_id).first()

    if not campaign:
        flash('Campaign not found or you do not have permission to update this campaign','error')
        return redirect(url_for('sponsor_dashboard'))

    if request.method == 'POST':
        campaign.name = request.form.get('name')
        campaign.budget = request.form.get('budget')
        campaign.goals = request.form.get('goals')
        campaign.niche = request.form.get('niche')
        campaign.visibility = request.form.get('visibility')

        db.session.commit()
        flash('Campaign updated successfully')
        return redirect(url_for('sponsor_dashboard'))
    return render_template('update_campaign.html',campaign=campaign)

@app.route('/campaign/<int:campaign_id>/delete', methods=['POST'])
@auth_rep
@check_campaign_editable
def delete_campaign(campaign_id):
    user_id = session.get('user_id')
    role_id = session.get('role_id')

    if role_id != 2:  # Ensure only sponsors can access this page
        flash('You do not have permission to access this page','error')
        return redirect(url_for('index'))

    campaign = Campaign.query.filter_by(campaign_id=campaign_id).first()

    if not campaign:
        flash('Campaign not found or you do not have permission to delete this campaign')
        return redirect(url_for('sponsor_dashboard'))

    campaign.campaign_status = 'deleted'
    db.session.commit()
    flash('Campaign marked as deleted')
    return redirect(url_for('sponsor_dashboard'))


@app.route('/profile', methods=['GET'])
@auth_rep
def user_profile():
    user_id=session['user_id']
    user = User.query.get(user_id)  
 
    if user.role_id == 3: 
        profile = InfluencerProfile.query.filter_by(id=user_id).first_or_404()
    elif user.role_id == 2:
        profile = Sponsor.query.filter_by(id=user_id).first_or_404()

    return render_template('profile.html', user=user, profile=profile, role_id=user.role_id)

@app.route('/profile/<int:user_id>', methods=['GET'])
@auth_rep
def view_profile(user_id):
    
    user = User.query.get(user_id)
    if user.role_id == 3:  # Influencer
        profile = InfluencerProfile.query.filter_by(id=user_id).first_or_404()
    elif user.role_id == 2:  # Sponsor
        profile = Sponsor.query.filter_by(id=user_id).first_or_404()
    else:
        profile = None
        flash('User role not recognized.', 'danger')

    return render_template('profile.html', user=user, profile=profile, role_id=user.role_id)


@app.route('/profile/update', methods=['GET', 'POST'])
@auth_rep
def update_profile():
    role_id = session.get('role_id') 
    user_id = session.get('user_id')  

    user = User.query.filter_by(id=user_id).first()

    if role_id == 3:
        profile = InfluencerProfile.query.filter_by(id=user_id).first_or_404()
    elif role_id == 2:
        profile = Sponsor.query.filter_by(id=user_id).first_or_404()

    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email_id = request.form.get('email')
        profile.name = request.form.get('name')
        profile.bio = request.form.get('bio')
        
        if role_id == 3:
            profile.niche = request.form.get('niche')
            profile.followers = request.form.get('followers')
        elif role_id == 2:
            profile.company_name = request.form.get('company_name')
            profile.budget = request.form.get('budget')
            profile.industry = request.form.get('industry')

        db.session.commit()
        flash('Profile updated successfully!','success')
        return redirect(url_for('user_profile'))

    return render_template('update_profile.html', user=user,profile=profile, role_id=role_id)

@app.route('/ad_request/<int:request_id>', methods=['GET'])
@auth_rep
def ad_request_details(request_id):
    ad_request = AdRequest.query.get_or_404(request_id)
    return render_template('ad_request_details.html', ad_request=ad_request)

@app.route('/add_ad_request', methods=['GET', 'POST'])
@auth_rep
def add_ad_request():
    if request.method == 'POST':
        campaign_id = request.form.get('campaign_id')
        created_for = request.form.get('created_for', '').strip().lower()
        print(f"Searching for username: {created_for}")

        messages = request.form.get('messages')
        requirements = request.form.get('requirements')
        payment_amount = request.form.get('payment_amount')
        user_role = session.get('role_id')

        campaign = Campaign.query.get(campaign_id)
        creator = User.query.get(session['user_id'])
        recipient = User.query.filter_by(username=created_for).first()
        
        # Check if the user is an influencer
        if user_role == 3:  # Influencer
            influencer = InfluencerProfile.query.filter_by(id=session['user_id']).first()
            sponsor = Sponsor.query.get(campaign.sponsor_id)
            if campaign.visibility == 'public' and influencer.niche == campaign.niche:
                new_request = AdRequest(
                    campaign_id=campaign_id,
                    created_by=creator.id,
                    created_for=sponsor.id,
                    messages=messages,
                    requirements=requirements,
                    payment_amount=payment_amount,
                    status='pending'
                )
            else:
                flash('You can only request for public campaigns matching your niche.', 'error')
                return redirect(url_for('add_ad_request'))
        elif user_role == 2:  # Sponsor
            influencer = InfluencerProfile.query.filter_by(id=recipient.id).first()
            if influencer.niche == campaign.niche:
                new_request = AdRequest(
                    campaign_id=campaign_id,
                    created_by=creator.id,
                    created_for=recipient.id,
                    messages=messages,
                    requirements=requirements,
                    payment_amount=payment_amount,
                    status='pending'
                )
            else:
                flash('The influencer niche must match the campaign niche.', 'error')
                return redirect(url_for('add_ad_request'))
        else:
            flash('Unauthorized action.', 'error')
            return redirect(url_for('add_ad_request'))

        db.session.add(new_request)
        db.session.commit()
        flash('Ad Request added successfully!','success')
        return redirect(url_for('campaign_details', campaign_id=campaign_id))

    # GET request: Display form
    campaigns = Campaign.query.all()
    users = User.query.filter(User.role_id == 3).all()  # Fetch influencers only

    return render_template('add_ad_request.html', campaigns=campaigns, users=users)

@app.route('/ad_request/edit/<int:request_id>', methods=['GET', 'POST'])
@auth_rep
@check_adr_editable
def edit_ad_request(request_id):
    ad_request = AdRequest.query.get(request_id)
    
    # Check if the current user is the creator of the ad request
    if session.get('user_id') != ad_request.created_by:
        flash('You do not have permission to edit this ad request.', 'danger')
        return redirect(url_for('ad_request_details', request_id=request_id))
    
    if request.method == 'POST':
        ad_request.created_for = request.form.get('created_for', ad_request.created_for)
        ad_request.messages = request.form.get('messages', ad_request.messages)
        ad_request.requirements = request.form.get('requirements', ad_request.requirements)
        ad_request.payment_amount = request.form.get('payment_amount', ad_request.payment_amount)
        ad_request.status = request.form.get('status', ad_request.status)
        
        db.session.commit()
        flash('Ad request updated successfully!', 'success')
        return redirect(url_for('ad_request_details', request_id=request_id))
    
    users = User.query.all()
    return render_template('edit_ad_request.html', ad_request=ad_request, users=users)


@app.route('/campaign_search', methods=['GET', 'POST'])
@auth_rep
def influencer_search():  #will be used by influencer and admin to search for campaigns
    
    if session['role_id'] == 1:
            query = Campaign.query
    else:
        id = session.get('user_id')
        influencer = InfluencerProfile.query.filter_by(id=id).first()
        query = Campaign.query.filter(
            Campaign.visibility == 'public',
            Campaign.niche == influencer.niche,
            Campaign.campaign_status == 'ongoing'
        )


    if request.method == 'POST':
        search_query = request.form.get('search_query', '')
        min_budget = request.form.get('min_budget', type=float)
        max_budget = request.form.get('max_budget', type=float)

        
        if search_query:
            query = query.filter(Campaign.name.ilike(f"%{search_query}%"))
        
        if min_budget is not None:
            query = query.filter(Campaign.budget >= min_budget)
        
        if max_budget is not None:
            query = query.filter(Campaign.budget <= max_budget)


    search_results = query.all()
    
    return render_template('campaign_search.html', search_results=search_results)

@app.route('/influencer_search', methods=['GET', 'POST'])
@auth_rep
def sponsor_search():  # will be used by sponsors and admin to search influencers 
    if session['role_id'] == 1:
        query = InfluencerProfile.query
    else:
       query = InfluencerProfile.query.join(User).filter(User.is_flagged == False)

    if request.method == 'POST':
        niche = request.form.get('niche', '')
        min_followers = request.form.get('min_followers', type=int)
        max_followers = request.form.get('max_followers', type=int)

        if niche:
            query = query.filter(InfluencerProfile.niche.ilike(f"%{niche}%"))

        if min_followers is not None:
            query = query.filter(InfluencerProfile.followers >= min_followers)

        if max_followers is not None:
            query = query.filter(InfluencerProfile.followers <= max_followers)

    search_results = query.all()

    return render_template('influencer_search.html', search_results=search_results)

@app.route('/search_sponsors', methods=['GET', 'POST'])
@auth_rep
def search_sponsors():  # Used by admin to search for sponsors
    if session['role_id'] == 1:
        query = Sponsor.query
    else:
        query = Sponsor.query.filter(Sponsor.is_flagged == False)

    if request.method == 'POST':
        search_query = request.form.get('search_query', '')
        min_budget = request.form.get('min_budget', type=float)
        max_budget = request.form.get('max_budget', type=float)
        industry = request.form.get('industry', '')

        if search_query:
            query = query.filter(Sponsor.name.ilike(f"%{search_query}%"))
        
        if industry:
            query = query.filter(Sponsor.industry.ilike(f"%{industry}%"))
        
        if min_budget is not None:
            query = query.filter(Sponsor.budget >= min_budget)
        
        if max_budget is not None:
            query = query.filter(Sponsor.budget <= max_budget)

    search_results = query.all()
    
    return render_template('search_sponsors.html', search_results=search_results)


@app.route('/accept_ad_request/<int:request_id>', methods=['POST'])
@auth_rep
@check_adr_editable
def accept_ad_request(request_id):
    ad_request = AdRequest.query.get(request_id)
    
    ad_request.status = 'ongoing'
    db.session.commit()
    flash('Ad Request accepted successfully.', 'success')
    if session['role_id']==3:
        return redirect(url_for('influencer_dashboard'))
    elif session['role_id']==2:
        return redirect(url_for('sponsor_dashboard'))

@app.route('/reject_ad_request/<int:request_id>', methods=['POST'])
@auth_rep
@check_adr_editable
def reject_ad_request(request_id):
    ad_request = AdRequest.query.get_or_404(request_id)

    ad_request.status = 'rejected'
    db.session.commit()
    flash('Ad Request rejected.', 'info')

    if session['role_id']==3:
        return redirect(url_for('influencer_dashboard'))
    elif session['role_id']==2:
        return redirect(url_for('sponsor_dashboard'))

