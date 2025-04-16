import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from dotenv import load_dotenv
import requests
from oauthlib.oauth2 import WebApplicationClient
import urllib3
from filters import register_filters
import os
import sys

# Allow OAuth over HTTP for development only
if os.getenv('FLASK_ENV') == 'development':
    import oauthlib.oauth2.rfc6749.errors
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Load environment variables
load_dotenv()

# For development only - disable SSL warnings
if os.getenv('FLASK_ENV') == 'development':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-for-testing')

# Configure database - use PostgreSQL in production if available
database_url = os.getenv('DATABASE_URL')
print(f"Raw DATABASE_URL: {database_url if database_url else 'Not set'}")

if database_url:
    # Fix for Render's PostgreSQL URL format
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print(f"Using PostgreSQL database: {database_url[:25]}...")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///opinions.db')
    print(f"Using SQLite database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEVELOPMENT_MODE'] = os.getenv('FLASK_ENV') == 'development'
print(f"Development mode: {app.config['DEVELOPMENT_MODE']}")

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Initialize SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Register custom Jinja2 filters
register_filters(app)

# Initialize OAuth client if credentials are provided
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    client = WebApplicationClient(GOOGLE_CLIENT_ID)
else:
    client = None

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    opinions = db.relationship('Opinion', backref='author', lazy=True)
    votes = db.relationship('Vote', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<Admin {self.username}>'

class Opinion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    votes = db.relationship('Vote', backref='opinion', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Opinion {self.title}>'

    @property
    def upvotes(self):
        return Vote.query.filter_by(opinion_id=self.id, vote_type=1).count()

    @property
    def downvotes(self):
        return Vote.query.filter_by(opinion_id=self.id, vote_type=-1).count()

    @property
    def score(self):
        return self.upvotes - self.downvotes

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    opinion_id = db.Column(db.Integer, db.ForeignKey('opinion.id'), nullable=False)
    vote_type = db.Column(db.Integer, nullable=False)  # 1 for upvote, -1 for downvote
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'opinion_id', name='user_opinion_uc'),)

    def __repr__(self):
        return f'<Vote {self.vote_type} on Opinion {self.opinion_id} by User {self.user_id}>'

# Create database tables
with app.app_context():
    try:
        # Debug database connection
        print(f"Database engine: {db.engine}")
        print(f"Database URL: {db.engine.url}")
        
        # Check if we're connected to PostgreSQL
        is_postgres = 'postgresql' in str(db.engine.url)
        print(f"Is PostgreSQL: {is_postgres}")
        
        # Create all tables
        db.create_all()
        print(f"Database tables created successfully on {'PostgreSQL' if is_postgres else 'SQLite'}")
        
        # List all tables to verify they were created
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"Created tables: {tables}")
        
        # In production, automatically create admin user if it doesn't exist
        if not app.config['DEVELOPMENT_MODE']:
            # Check if admin user exists, if not create one
            admin_exists = Admin.query.filter_by(username=os.getenv('ADMIN_USERNAME')).first()
            if not admin_exists and os.getenv('ADMIN_USERNAME') and os.getenv('ADMIN_PASSWORD'):
                admin = Admin(username=os.getenv('ADMIN_USERNAME'))
                
                # Handle plain text password in .env
                password = os.getenv('ADMIN_PASSWORD')
                if password and (password.startswith('pbkdf2:') or password.startswith('scrypt:')):
                    admin.password_hash = password  # It's already a hash
                elif password:
                    admin.set_password(password)  # Generate hash from plain text
                else:
                    print("WARNING: ADMIN_PASSWORD not set")
                    
                db.session.add(admin)
                db.session.commit()
                
                # Create admin user in User table for login
                user = User.query.filter_by(email=f"{os.getenv('ADMIN_USERNAME')}@admin.local").first()
                if not user:
                    user = User(
                        email=f"{os.getenv('ADMIN_USERNAME')}@admin.local",
                        name=f"Admin: {os.getenv('ADMIN_USERNAME')}",
                        is_admin=True
                    )
                    db.session.add(user)
                    db.session.commit()
                print(f"Admin user '{os.getenv('ADMIN_USERNAME')}' created successfully")
                
                # Add sample opinions if none exist
                if Opinion.query.count() == 0:
                    sample_opinions = [
                        Opinion(title="The Uncertainty of AI", content="AI systems face fundamental uncertainty in real-world applications due to the complexity of human behavior and societal contexts.", user_id=user.id),
                        Opinion(title="Climate Change Predictions", content="Despite advanced models, climate change predictions contain unquantifiable uncertainties related to human behavior and complex feedback loops.", user_id=user.id),
                        Opinion(title="Economic Forecasting Limitations", content="Economic forecasts often fail because they attempt to quantify inherently uncertain human behaviors and market psychology.", user_id=user.id)
                    ]
                    for opinion in sample_opinions:
                        db.session.add(opinion)
                    db.session.commit()
                    print(f"Added {len(sample_opinions)} sample opinions")
    except Exception as e:
        print(f"Error in database initialization: {e}")
        import traceback
        traceback.print_exc()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    opinions = Opinion.query.order_by(Opinion.created_at.desc()).all()
    return render_template('index.html', opinions=opinions)

@app.route('/login')
def login():
    # In development mode with no valid Google credentials, redirect to dev login
    if app.config['DEVELOPMENT_MODE'] and (not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET):
        return redirect(url_for('dev_login'))
    return render_template('login.html')

@app.route('/login/google')
def login_google():
    # For development, provide a mock login if Google credentials aren't set
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Google OAuth credentials are not configured. Using development login.', 'info')
        return redirect(url_for('dev_login'))
    
    if client is None:
        flash('OAuth client is not initialized. Check your Google credentials.', 'danger')
        return redirect(url_for('login'))
    
    # Find out what URL to hit for Google login
    try:
        # Print credentials for debugging (only in development mode)
        if app.config['DEVELOPMENT_MODE']:
            print(f"Using Google Client ID: {GOOGLE_CLIENT_ID[:10]}...")
            print(f"Client Secret is set: {'Yes' if GOOGLE_CLIENT_SECRET else 'No'}")
            
        # In development mode, don't verify SSL certificates
        verify_ssl = not app.config['DEVELOPMENT_MODE']
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL, verify=verify_ssl).json()
        authorization_endpoint = google_provider_cfg["authorization_endpoint"]

        # Use library to construct the request for Google login and provide
        # scopes that let you retrieve user's profile from Google
        # Use different redirect URIs for development and production
        if app.config['DEVELOPMENT_MODE']:
            redirect_uri = "http://127.0.0.1:5000/login/google/callback"
        else:
            redirect_uri = url_for('callback', _external=True)
            
        if app.config['DEVELOPMENT_MODE']:
            print(f"Redirect URI: {redirect_uri}")
            
        request_uri = client.prepare_request_uri(
            authorization_endpoint,
            redirect_uri=redirect_uri,
            scope=["openid", "email", "profile"],
        )
        return redirect(request_uri)
    except Exception as e:
        error_msg = str(e)
        print(f"Google OAuth Error: {error_msg}")
        flash(f'Error connecting to Google: {error_msg}', 'danger')
        return redirect(url_for('login'))

@app.route('/login/google/callback')
def callback():
    # Get authorization code Google sent back
    code = request.args.get("code")
    if not code:
        flash("No authorization code received from Google", 'danger')
        return redirect(url_for('login'))
    
    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    try:
        verify_ssl = not app.config['DEVELOPMENT_MODE']
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL, verify=verify_ssl).json()
        token_endpoint = google_provider_cfg["token_endpoint"]
        
        # Prepare and send a request to get tokens
        # Use different redirect URIs for development and production
        if app.config['DEVELOPMENT_MODE']:
            redirect_uri = "http://127.0.0.1:5000/login/google/callback"
        else:
            redirect_uri = url_for('callback', _external=True)
            
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=redirect_uri,
            code=code
        )
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
            verify=verify_ssl
        )

        # Parse the tokens
        client.parse_request_body_response(json.dumps(token_response.json()))
        
        # Now that you have tokens, let's find and hit the URL
        # from Google that gives you the user's profile information
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body, verify=verify_ssl)
        
        # Make sure their email is verified
        if userinfo_response.json().get("email_verified"):
            unique_id = userinfo_response.json()["sub"]
            users_email = userinfo_response.json()["email"]
            picture = userinfo_response.json().get("picture", "")
            users_name = userinfo_response.json().get("name", "")
        else:
            flash("User email not verified by Google.", 'warning')
            return redirect(url_for("login"))
        
        # Check if user exists, if not create a new one
        user = User.query.filter_by(email=users_email).first()
        if not user:
            user = User(email=users_email, name=users_name, profile_pic=picture)
            db.session.add(user)
            db.session.commit()
            flash(f"Welcome {users_name}! Your account has been created.", 'success')
        else:
            flash(f"Welcome back, {users_name}!", 'success')
        
        # Begin user session by logging the user in
        login_user(user)
        
        # Send user back to homepage
        return redirect(url_for("index"))
    except Exception as e:
        error_msg = str(e)
        print(f"Google OAuth Error during callback: {error_msg}")
        flash(f'Error during Google authentication: {error_msg}', 'danger')
        return redirect(url_for('login'))

@app.route('/dev-login')
def dev_login():
    if not app.config['DEVELOPMENT_MODE']:
        flash('Development login is only available in development mode.', 'danger')
        return redirect(url_for('login'))
    
    return render_template('dev_login.html')

@app.route('/dev-login', methods=['POST'])
def dev_login_post():
    if not app.config['DEVELOPMENT_MODE']:
        flash('Development login is only available in development mode.', 'danger')
        return redirect(url_for('login'))
    
    email = request.form.get('email')
    name = request.form.get('name')
    
    if not email or not name:
        flash('Email and name are required', 'danger')
        return redirect(url_for('dev_login'))
    
    # Check if user exists, if not create a new one
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, name=name, profile_pic="")
        db.session.add(user)
        db.session.commit()
    
    # Begin user session by logging the user in
    login_user(user)
    
    flash('Logged in successfully with development account!', 'success')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
def admin_login():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')

@app.route('/admin/login', methods=['POST'])
def admin_login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    
    admin = Admin.query.filter_by(username=username).first()
    
    if not admin:
        flash('Please check your login details and try again.', 'danger')
        return redirect(url_for('admin_login'))
    
    # Check password using the model's method
    if not admin.check_password(password):
        flash('Please check your login details and try again.', 'danger')
        return redirect(url_for('admin_login'))
    
    # If admin exists and password is correct, find or create user object
    user = User.query.filter_by(email=f"{username}@admin.local").first()
    if not user:
        user = User(
            email=f"{username}@admin.local",
            name=f"Admin: {username}",
            is_admin=True
        )
        db.session.add(user)
        db.session.commit()
    else:
        # Ensure the user is marked as admin
        user.is_admin = True
        db.session.commit()
    
    login_user(user)
    flash('Logged in successfully as admin!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access the admin dashboard.')
        return redirect(url_for('index'))
    
    opinions = Opinion.query.order_by(Opinion.created_at.desc()).all()
    return render_template('admin_dashboard.html', opinions=opinions)

@app.route('/opinion/new', methods=['GET', 'POST'])
@login_required
def new_opinion():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        if not title or not content:
            flash('Title and content are required!')
            return redirect(url_for('new_opinion'))
        
        opinion = Opinion(title=title, content=content, user_id=current_user.id)
        db.session.add(opinion)
        db.session.commit()
        
        flash('Your opinion has been added!')
        return redirect(url_for('index'))
    
    return render_template('new_opinion.html')

@app.route('/opinion/<int:opinion_id>')
def view_opinion(opinion_id):
    opinion = Opinion.query.get_or_404(opinion_id)
    return render_template('view_opinion.html', opinion=opinion)

@app.route('/opinion/<int:opinion_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_opinion(opinion_id):
    opinion = Opinion.query.get_or_404(opinion_id)
    
    # Check if user is the author or an admin
    if opinion.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to edit this opinion.')
        return redirect(url_for('view_opinion', opinion_id=opinion.id))
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        if not title or not content:
            flash('Title and content are required!')
            return redirect(url_for('edit_opinion', opinion_id=opinion.id))
        
        opinion.title = title
        opinion.content = content
        opinion.updated_at = datetime.utcnow()
        db.session.commit()
        
        flash('Opinion has been updated!')
        return redirect(url_for('view_opinion', opinion_id=opinion.id))
    
    return render_template('edit_opinion.html', opinion=opinion)

@app.route('/opinion/<int:opinion_id>/delete', methods=['POST'])
@login_required
def delete_opinion(opinion_id):
    opinion = Opinion.query.get_or_404(opinion_id)
    
    # Check if user is the author or an admin
    if opinion.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this opinion.')
        return redirect(url_for('view_opinion', opinion_id=opinion.id))
    
    db.session.delete(opinion)
    db.session.commit()
    
    flash('Opinion has been deleted!')
    return redirect(url_for('index'))

@app.route('/opinion/<int:opinion_id>/vote', methods=['POST'])
@login_required
def vote_opinion(opinion_id):
    opinion = Opinion.query.get_or_404(opinion_id)
    vote_type = int(request.form.get('vote_type'))  # 1 for upvote, -1 for downvote
    
    if vote_type not in [1, -1]:
        return jsonify({'error': 'Invalid vote type'}), 400
    
    # Check if user has already voted
    existing_vote = Vote.query.filter_by(user_id=current_user.id, opinion_id=opinion.id).first()
    
    if existing_vote:
        if existing_vote.vote_type == vote_type:
            # If voting the same way, remove the vote
            db.session.delete(existing_vote)
        else:
            # If voting differently, update the vote
            existing_vote.vote_type = vote_type
    else:
        # Create a new vote
        vote = Vote(user_id=current_user.id, opinion_id=opinion.id, vote_type=vote_type)
        db.session.add(vote)
    
    db.session.commit()
    
    # Return updated vote counts
    return jsonify({
        'upvotes': opinion.upvotes,
        'downvotes': opinion.downvotes,
        'score': opinion.score
    })

@app.route('/admin/init', methods=['GET'])
def init_admin():
    # Check if admin user exists
    admin_exists = Admin.query.filter_by(username=os.getenv('ADMIN_USERNAME')).first()
    
    if not admin_exists and os.getenv('ADMIN_USERNAME') and os.getenv('ADMIN_PASSWORD'):
        admin = Admin(username=os.getenv('ADMIN_USERNAME'))
        admin.set_password(os.getenv('ADMIN_PASSWORD'))
        db.session.add(admin)
        db.session.commit()
        return jsonify({'message': 'Admin user created successfully'})
    
    return jsonify({'message': 'Admin user already exists or environment variables not set'})

@app.route('/init-db')
def init_db():
    if not app.config['DEVELOPMENT_MODE']:
        return jsonify({'error': 'This route is only available in development mode'}), 403
        
    try:
        db.create_all()
        # Check if admin user exists, if not create one
        admin_exists = Admin.query.filter_by(username=os.getenv('ADMIN_USERNAME')).first()
        if not admin_exists and os.getenv('ADMIN_USERNAME') and os.getenv('ADMIN_PASSWORD'):
            admin = Admin(username=os.getenv('ADMIN_USERNAME'))
            
            # Handle plain text password in .env
            password = os.getenv('ADMIN_PASSWORD')
            if password.startswith('pbkdf2:') or password.startswith('scrypt:'):
                admin.password_hash = password  # It's already a hash
            else:
                admin.set_password(password)  # Generate hash from plain text
                
            db.session.add(admin)
            db.session.commit()
            
            # Create admin user in User table for login
            user = User.query.filter_by(email=f"{os.getenv('ADMIN_USERNAME')}@admin.local").first()
            if not user:
                user = User(
                    email=f"{os.getenv('ADMIN_USERNAME')}@admin.local",
                    name=f"Admin: {os.getenv('ADMIN_USERNAME')}",
                    is_admin=True
                )
                db.session.add(user)
                db.session.commit()
        
        return jsonify({'message': 'Database initialized successfully!', 'admin_created': not admin_exists})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/init-production-db')
def init_production_db():
    # This should only be called once when deploying to production
    # We'll use a simple token-based authentication to prevent unauthorized access
    token = request.args.get('token')
    if not token or token != os.getenv('SECRET_KEY')[:10]:  # Use first 10 chars of SECRET_KEY as a simple token
        return jsonify({'error': 'Unauthorized access'}), 403
        
    try:
        db.create_all()
        # Check if admin user exists, if not create one
        admin_exists = Admin.query.filter_by(username=os.getenv('ADMIN_USERNAME')).first()
        if not admin_exists and os.getenv('ADMIN_USERNAME') and os.getenv('ADMIN_PASSWORD'):
            admin = Admin(username=os.getenv('ADMIN_USERNAME'))
            
            # Handle plain text password in .env
            password = os.getenv('ADMIN_PASSWORD')
            if password.startswith('pbkdf2:') or password.startswith('scrypt:'):
                admin.password_hash = password  # It's already a hash
            else:
                admin.set_password(password)  # Generate hash from plain text
                
            db.session.add(admin)
            db.session.commit()
            
            # Create admin user in User table for login
            user = User.query.filter_by(email=f"{os.getenv('ADMIN_USERNAME')}@admin.local").first()
            if not user:
                user = User(
                    email=f"{os.getenv('ADMIN_USERNAME')}@admin.local",
                    name=f"Admin: {os.getenv('ADMIN_USERNAME')}",
                    is_admin=True
                )
                db.session.add(user)
                db.session.commit()
        
        # Create some sample opinions if the database is empty
        if Opinion.query.count() == 0:
            sample_opinions = [
                {
                    'title': 'Climate Change Tipping Points',
                    'content': 'The uncertainty around climate tipping points represents a significant challenge. While we can model general warming trends, predicting exactly when systems like the Amazon rainforest or Arctic sea ice will reach irreversible tipping points remains highly uncertain.',
                    'author_email': f"{os.getenv('ADMIN_USERNAME')}@admin.local"
                },
                {
                    'title': 'Artificial General Intelligence Timeline',
                    'content': 'The timeline for achieving artificial general intelligence (AGI) involves unquantifiable uncertainty. Despite progress in machine learning, we cannot reliably estimate when or if AI will reach human-level general intelligence, making it difficult to prepare for potential impacts.',
                    'author_email': f"{os.getenv('ADMIN_USERNAME')}@admin.local"
                },
                {
                    'title': 'Pandemic Preparedness',
                    'content': 'Future pandemic risks involve deep uncertainty. While we can identify some potential pathogens, the emergence of novel diseases with unknown characteristics represents an unquantifiable uncertainty that challenges our ability to prepare adequate responses.',
                    'author_email': f"{os.getenv('ADMIN_USERNAME')}@admin.local"
                }
            ]
            
            for opinion_data in sample_opinions:
                user = User.query.filter_by(email=opinion_data['author_email']).first()
                if user:
                    opinion = Opinion(
                        title=opinion_data['title'],
                        content=opinion_data['content'],
                        user_id=user.id
                    )
                    db.session.add(opinion)
            
            db.session.commit()
        
        return jsonify({
            'message': 'Production database initialized successfully!', 
            'admin_created': not admin_exists,
            'sample_data_added': Opinion.query.count() > 0
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Helper context processor for templates
@app.context_processor
def utility_processor():
    def user_vote(opinion_id):
        if not current_user.is_authenticated:
            return 0
        vote = Vote.query.filter_by(user_id=current_user.id, opinion_id=opinion_id).first()
        return vote.vote_type if vote else 0
    
    return dict(user_vote=user_vote)

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

if __name__ == '__main__':
    # Use PORT environment variable for production (Render sets this)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=app.config['DEVELOPMENT_MODE'])
