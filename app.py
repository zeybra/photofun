from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_pymongo import PyMongo
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from models import User
from challenges import create_challenges_for_session, get_available_sets, CHALLENGE_SETS
import os
import uuid
import time
from dotenv import load_dotenv
from pywebpush import webpush, WebPushException
import json
import bleach
import re
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import requests
import cloudinary
import cloudinary.uploader

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
app.config["MONGO_URI"] = os.getenv('MONGO_URI', "mongodb://localhost:27017/photo_challenge")
app.config['WTF_CSRF_ENABLED'] = True

# Google OAuth config
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow HTTP for development

# Cloudinary configuration for photo storage
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

# Admin configuration
ADMIN_EMAIL = 'johan.kire@gmail.com'

# Initialize allowed emails from env (for first setup)
def init_allowed_emails():
    """Initialize allowed emails from env file if none exist in database"""
    if mongo.db.allowed_emails.count_documents({}) == 0:
        env_emails = os.getenv('ALLOWED_EMAILS', '').split(',')
        env_emails = [email.strip().lower() for email in env_emails if email.strip()]

        # Always ensure admin email is included
        if ADMIN_EMAIL.lower() not in env_emails:
            env_emails.append(ADMIN_EMAIL.lower())

        for email in env_emails:
            mongo.db.allowed_emails.insert_one({
                'email': email,
                'added_by': 'system',
                'added_at': datetime.now()
            })

def get_allowed_emails():
    """Get current list of allowed emails from database"""
    return [doc['email'] for doc in mongo.db.allowed_emails.find()]

def is_admin(email):
    """Check if user is admin"""
    return email.lower() == ADMIN_EMAIL.lower()

# File upload config
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Security extensions
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

mongo = PyMongo(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Input validation helpers
def sanitize_input(text, max_length=100):
    """Sanitize and validate text input"""
    if not text:
        return ''
    # Strip whitespace and limit length
    text = str(text).strip()[:max_length]
    # Remove any HTML/script tags
    text = bleach.clean(text, tags=[], strip=True)
    return text

def validate_session_name(name):
    """Validate session name"""
    if not name or len(name.strip()) < 3:
        return False, "Session name must be at least 3 characters long"
    if len(name) > 50:
        return False, "Session name too long (max 50 characters)"
    # Allow alphanumeric, spaces, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9\s\-_]+$', name):
        return False, "Session name contains invalid characters"
    return True, ""

# Security headers
@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Temporarily disable CSP for testing
    # response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://accounts.google.com; style-src 'self' 'unsafe-inline' https://accounts.google.com; connect-src 'self' https://accounts.google.com; frame-src https://accounts.google.com"
    return response

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get user's sessions (where they are a participant)
    user_id = session['user_id']
    user_sessions = list(mongo.db.sessions.find(
        {'participants': user_id}
    ).sort('created_at', -1))

    # Add session IDs as strings for template
    for sess in user_sessions:
        sess['id'] = str(sess['_id'])

    return render_template('home.html', sessions=user_sessions)

# Google OAuth routes
@app.route('/login')
def login():
    if GOOGLE_CLIENT_ID:
        return render_template('login.html', google_client_id=GOOGLE_CLIENT_ID)
    else:
        flash('Google OAuth not configured. Please set GOOGLE_CLIENT_ID in environment.')
        return render_template('login.html')

@app.route('/auth/google', methods=['POST'])
@limiter.limit("10 per minute")
@csrf.exempt
def google_auth():
    # Get the token from the request
    token = request.json.get('credential')

    if not token:
        return jsonify({'error': 'No token provided'}), 400

    try:
        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID)

        # Get user info
        email = idinfo['email']
        name = idinfo['name']
        google_id = idinfo['sub']

        # Initialize allowed emails on first run
        init_allowed_emails()

        # Check if email is allowed
        allowed_emails = get_allowed_emails()
        if email.lower() not in allowed_emails:
            return jsonify({'error': f'Access denied. {email} is not authorized to use this app.'}), 403

        # Check if user exists
        user_doc = mongo.db.users.find_one({'google_id': google_id})

        if not user_doc:
            # Create new user
            user_doc = {
                'google_id': google_id,
                'email': email,
                'name': name,
                'username': name.split()[0] if name else email.split('@')[0],
                'created_at': datetime.now()
            }
            result = mongo.db.users.insert_one(user_doc)
            user_doc['_id'] = result.inserted_id

        # Set session
        session['user_id'] = str(user_doc['_id'])
        session['username'] = user_doc['username']
        session['email'] = user_doc['email']
        session.permanent = True
        app.permanent_session_lifetime = timedelta(hours=24)

        return jsonify({'success': True, 'redirect': url_for('home')})

    except ValueError as e:
        return jsonify({'error': 'Invalid token'}), 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Admin routes
@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if not is_admin(session.get('email', '')):
        flash('Access denied. Admin only.')
        return redirect(url_for('home'))

    # Get all allowed emails and users
    allowed_emails = list(mongo.db.allowed_emails.find().sort('added_at', -1))
    users = list(mongo.db.users.find().sort('created_at', -1))

    # Get available challenge sets
    challenge_sets = get_available_sets()

    return render_template('admin.html',
                         allowed_emails=allowed_emails,
                         users=users,
                         challenge_sets=challenge_sets)

@app.route('/admin/add-email', methods=['POST'])
@limiter.limit("10 per minute")
def add_allowed_email():
    if 'user_id' not in session or not is_admin(session.get('email', '')):
        return jsonify({'error': 'Access denied'}), 403

    email = request.form.get('email', '').strip().lower()
    if not email:
        flash('Email address is required!')
        return redirect(url_for('admin'))

    # Validate email format
    if '@' not in email or '.' not in email.split('@')[1]:
        flash('Invalid email format!')
        return redirect(url_for('admin'))

    # Check if already exists
    if mongo.db.allowed_emails.find_one({'email': email}):
        flash(f'{email} is already in the allowed list!')
        return redirect(url_for('admin'))

    # Add to database
    mongo.db.allowed_emails.insert_one({
        'email': email,
        'added_by': session['email'],
        'added_at': datetime.now()
    })

    flash(f'Added {email} to allowed users!')
    return redirect(url_for('admin'))

@app.route('/admin/remove-email', methods=['POST'])
@limiter.limit("10 per minute")
def remove_allowed_email():
    if 'user_id' not in session or not is_admin(session.get('email', '')):
        return jsonify({'error': 'Access denied'}), 403

    email = request.form.get('email', '').strip().lower()

    # Don't allow removing admin email
    if email == ADMIN_EMAIL.lower():
        flash('Cannot remove admin email!')
        return redirect(url_for('admin'))

    # Remove from database
    result = mongo.db.allowed_emails.delete_one({'email': email})
    if result.deleted_count > 0:
        flash(f'Removed {email} from allowed users!')
    else:
        flash(f'{email} was not found in the allowed list!')

    return redirect(url_for('admin'))

@app.route('/admin/challenges/<challenge_set>')
def admin_challenges(challenge_set):
    if 'user_id' not in session or not is_admin(session.get('email', '')):
        flash('Access denied. Admin only.')
        return redirect(url_for('home'))

    if challenge_set not in CHALLENGE_SETS:
        flash('Challenge set not found!')
        return redirect(url_for('admin'))

    challenges = CHALLENGE_SETS[challenge_set]['challenges']
    set_info = CHALLENGE_SETS[challenge_set]

    return render_template('admin_challenges.html',
                         challenge_set=challenge_set,
                         set_info=set_info,
                         challenges=challenges)

@app.route('/admin/challenges/<challenge_set>/edit/<int:challenge_index>', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def edit_challenge(challenge_set, challenge_index):
    if 'user_id' not in session or not is_admin(session.get('email', '')):
        flash('Access denied. Admin only.')
        return redirect(url_for('home'))

    if challenge_set not in CHALLENGE_SETS:
        flash('Challenge set not found!')
        return redirect(url_for('admin'))

    if challenge_index >= len(CHALLENGE_SETS[challenge_set]['challenges']):
        flash('Challenge not found!')
        return redirect(url_for('admin_challenges', challenge_set=challenge_set))

    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', ''), 100)
        description = sanitize_input(request.form.get('description', ''), 500)

        if not title or not description:
            flash('Title and description are required!')
            return redirect(url_for('edit_challenge', challenge_set=challenge_set, challenge_index=challenge_index))

        # Update the challenge in memory (this is temporary - in production you'd save to a file)
        CHALLENGE_SETS[challenge_set]['challenges'][challenge_index] = {
            'title': title,
            'description': description
        }

        flash(f'Challenge {challenge_index + 1} updated successfully!')
        return redirect(url_for('admin_challenges', challenge_set=challenge_set))

    challenge = CHALLENGE_SETS[challenge_set]['challenges'][challenge_index]
    return render_template('edit_challenge.html',
                         challenge_set=challenge_set,
                         challenge_index=challenge_index,
                         challenge=challenge)

@app.route('/admin/download-originals/<session_id>')
def download_originals(session_id):
    if 'user_id' not in session or not is_admin(session.get('email', '')):
        flash('Access denied. Admin only.')
        return redirect(url_for('home'))

    # Get session info
    session_doc = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})
    if not session_doc:
        flash('Session not found!')
        return redirect(url_for('admin'))

    # Get all photos for this session
    photos = list(mongo.db.photos.find({'session_id': session_id}))

    # Create download links for originals
    download_links = []
    for photo in photos:
        if 'original_url' in photo:
            download_links.append({
                'filename': photo.get('original_filename', f"photo_{photo['_id']}.jpg"),
                'url': photo['original_url'],
                'uploader': photo['uploader_name'],
                'uploaded_at': photo['uploaded_at']
            })

    return render_template('download_originals.html',
                         session=session_doc,
                         download_links=download_links,
                         session_id=session_id)

# Session management routes
@app.route('/create-session', methods=['GET', 'POST'])
def create_session():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        session_name = sanitize_input(request.form.get('session_name', ''), 50)

        # Validate session name
        is_valid, error_msg = validate_session_name(session_name)
        if not is_valid:
            flash(error_msg)
            return render_template('create_session.html')

        start_time = datetime.now()  # Start immediately for now

        # Get number of challenges and interval
        try:
            number_of_challenges = int(request.form.get('number_of_challenges', 10))
            if number_of_challenges < 1 or number_of_challenges > 10:
                number_of_challenges = 10
        except ValueError:
            number_of_challenges = 10

        try:
            interval_minutes = int(request.form.get('interval_minutes', 60))
            if interval_minutes < 1 or interval_minutes > 1440:  # Max 24 hours
                interval_minutes = 60
        except ValueError:
            interval_minutes = 60

        # Create session in MongoDB
        session_doc = {
            'name': session_name,
            'start_time': start_time,
            'number_of_challenges': number_of_challenges,
            'interval_minutes': interval_minutes,
            'created_by': session['user_id'],
            'created_by_name': session['username'],
            'created_at': datetime.now(),
            'participants': [session['user_id']]
        }

        result = mongo.db.sessions.insert_one(session_doc)
        session_id = str(result.inserted_id)

        # Create challenges for this session
        challenge_set = request.form.get('challenge_set', 'prague')
        create_challenges_for_session(session_id, challenge_set, number_of_challenges)
        
        flash(f'Adventure "{session_name}" created successfully!')
        return redirect(url_for('session_view', session_id=session_id))
    
    return render_template('create_session.html')

@app.route('/join-session')
def join_session():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('join_session.html')

@app.route('/session/<session_id>/delete', methods=['POST'])
def delete_session(session_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    # Get session from database
    session_doc = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})
    if not session_doc:
        return jsonify({'error': 'Adventure not found'}), 404

    # Check if user is the creator
    if session_doc['created_by'] != session['user_id']:
        return jsonify({'error': 'Only the creator can delete this adventure'}), 403

    # Delete all challenges for this session
    mongo.db.challenges.delete_many({'session_id': session_id})

    # Delete all photos for this session
    mongo.db.photos.delete_many({'session_id': session_id})

    # Delete the session
    mongo.db.sessions.delete_one({'_id': ObjectId(session_id)})

    return jsonify({'success': True})

@app.route('/session/<session_id>')
def session_view(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get session from database
    session_doc = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})
    if not session_doc:
        flash('Adventure not found!')
        return redirect(url_for('home'))

    # Add user to participants if not already there
    current_user_id = session['user_id']
    participants = session_doc.get('participants', [])
    if current_user_id not in participants:
        mongo.db.sessions.update_one(
            {'_id': ObjectId(session_id)},
            {'$addToSet': {'participants': current_user_id}}
        )
        flash(f'You joined the adventure: {session_doc["name"]}!')

    # Calculate current challenge based on interval
    start_time = session_doc['start_time']
    current_time = datetime.now()
    interval_minutes = session_doc.get('interval_minutes', 60)
    minutes_elapsed = (current_time - start_time).total_seconds() / 60
    current_challenge_number = int(minutes_elapsed / interval_minutes) + 1

    # Get only current and past challenges (hide future ones for suspense!)
    all_challenges = list(mongo.db.challenges.find({'session_id': session_id}).sort('hour', 1))
    visible_challenges = [c for c in all_challenges if c['hour'] <= current_challenge_number]

    # Check if user has uploaded any photos
    user_has_photos = mongo.db.photos.count_documents({
        'session_id': session_id,
        'uploader_id': current_user_id
    }) > 0

    return render_template('session_view.html',
                         session=session_doc,
                         challenges=visible_challenges,
                         current_challenge_hour=current_challenge_number,
                         total_challenges=len(all_challenges),
                         session_id=session_id,
                         user_has_photos=user_has_photos)

@app.route('/session/<session_id>/upload', methods=['GET', 'POST'])
def upload_photos(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    session_doc = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})
    if not session_doc:
        flash('Adventure not found!')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        if 'photos' not in request.files:
            flash('No photos selected!')
            return redirect(request.url)
        
        files = request.files.getlist('photos')
        uploaded_count = 0
        
        for file in files:
            if file and file.filename != '':
                try:
                    # Upload to Cloudinary instead of local storage
                    timestamp = str(int(time.time()))
                    public_id = f"photofun/{session_id}/{timestamp}_{session['username']}"

                    # Upload original (full quality, no transformation)
                    original_result = cloudinary.uploader.upload(
                        file,
                        public_id=f"{public_id}_original",
                        folder="photofun/originals",
                        resource_type="image"
                    )

                    # CRITICAL: Reset file stream to beginning
                    file.seek(0)

                    # Upload display version (optimized for web)
                    display_result = cloudinary.uploader.upload(
                        file,
                        public_id=public_id,
                        folder="photofun",
                        resource_type="image",
                        transformation=[
                            {'width': 1200, 'height': 1200, 'crop': 'limit'},
                            {'quality': 'auto:good'}
                        ]
                    )
                    # Save to database with both URLs
                    photo_doc = {
                        'session_id': session_id,
                        'uploader_id': session['user_id'],
                        'uploader_name': session['username'],
                        'filename': display_result['public_id'],
                        'url': display_result['secure_url'],           # Optimized for display
                        'original_url': original_result['secure_url'], # Full quality original
                        'original_filename': secure_filename(file.filename),
                        'challenge_ids': [],  # Can be assigned to multiple challenges
                        'uploaded_at': datetime.now()
                    }
                    mongo.db.photos.insert_one(photo_doc)
                    uploaded_count += 1

                except Exception as e:
                    print(f"Upload failed for {file.filename}: {e}")
                    # Continue with other files
        
        flash(f'Successfully uploaded {uploaded_count} photos!')

        # Send notification to other participants
        session_doc = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})
        if session_doc:
            send_notification_to_session(
                session_id,
                f"New photos uploaded!",
                f"{session['username']} uploaded {uploaded_count} photos to {session_doc['name']}",
                exclude_user_id=session['user_id']
            )

        return redirect(url_for('categorize_photos', session_id=session_id))
    
    # Get only available challenges (current and past)
    start_time = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})['start_time']
    hours_elapsed = (datetime.now() - start_time).total_seconds() / 3600
    current_challenge_hour = int(hours_elapsed) + 1

    all_challenges = list(mongo.db.challenges.find({'session_id': session_id}).sort('hour', 1))
    challenges = [c for c in all_challenges if c['hour'] <= current_challenge_hour]
    
    return render_template('upload_photos.html', 
                         session=session_doc, 
                         challenges=challenges,
                         session_id=session_id)

@app.route('/session/<session_id>/categorize')
def categorize_photos(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get all photos for current user (we show all now, with checkmarks for assigned)
    photos = list(mongo.db.photos.find({
        'session_id': session_id,
        'uploader_id': session['user_id']
    }))

    # Migrate old photos to new schema if needed
    for photo in photos:
        if 'challenge_id' in photo and photo['challenge_id'] is not None:
            # Old schema: single challenge_id
            mongo.db.photos.update_one(
                {'_id': photo['_id']},
                {
                    '$set': {'challenge_ids': [photo['challenge_id']]},
                    '$unset': {'challenge_id': ''}
                }
            )
            photo['challenge_ids'] = [photo['challenge_id']]
        elif 'challenge_ids' not in photo:
            # No challenge_ids field at all
            photo['challenge_ids'] = []

    # Sort photos: unassigned first, then assigned
    photos.sort(key=lambda p: len(p.get('challenge_ids', [])) > 0)

    session_doc = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})

    # Get only available challenges (current and past)
    start_time = session_doc['start_time']
    interval_minutes = session_doc.get('interval_minutes', 60)
    minutes_elapsed = (datetime.now() - start_time).total_seconds() / 60
    current_challenge_number = int(minutes_elapsed / interval_minutes) + 1

    all_challenges = list(mongo.db.challenges.find({'session_id': session_id}).sort('hour', 1))
    challenges = [c for c in all_challenges if c['hour'] <= current_challenge_number]

    return render_template('categorize_photos.html',
                         photos=photos,
                         challenges=challenges,
                         session=session_doc,
                         session_id=session_id)

@app.route('/assign-photo', methods=['POST'])
@csrf.exempt
def assign_photo():
    photo_id = request.form['photo_id']
    challenge_id = request.form['challenge_id']
    action = request.form.get('action', 'toggle')  # 'toggle', 'add', or 'remove'

    photo = mongo.db.photos.find_one({'_id': ObjectId(photo_id)})
    if not photo:
        return jsonify({'error': 'Photo not found'}), 404

    # Get current challenge_ids (handle old schema)
    if 'challenge_ids' in photo:
        challenge_ids = photo['challenge_ids']
    elif 'challenge_id' in photo and photo['challenge_id']:
        challenge_ids = [photo['challenge_id']]
    else:
        challenge_ids = []

    # Toggle or add/remove challenge
    if action == 'toggle':
        if challenge_id in challenge_ids:
            challenge_ids.remove(challenge_id)
        else:
            challenge_ids.append(challenge_id)
    elif action == 'add' and challenge_id not in challenge_ids:
        challenge_ids.append(challenge_id)
    elif action == 'remove' and challenge_id in challenge_ids:
        challenge_ids.remove(challenge_id)

    # Update database
    mongo.db.photos.update_one(
        {'_id': ObjectId(photo_id)},
        {
            '$set': {'challenge_ids': challenge_ids},
            '$unset': {'challenge_id': ''}  # Remove old field if present
        }
    )

    return jsonify({
        'success': True,
        'challenge_ids': challenge_ids,
        'is_assigned': challenge_id in challenge_ids
    })

@app.route('/photo/<photo_id>/delete', methods=['POST'])
@csrf.exempt
def delete_photo(photo_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    photo = mongo.db.photos.find_one({'_id': ObjectId(photo_id)})
    if not photo:
        return jsonify({'error': 'Photo not found'}), 404

    # Check if user owns this photo
    if photo['uploader_id'] != session['user_id']:
        return jsonify({'error': 'You can only delete your own photos'}), 403

    # Delete from Cloudinary if URL exists
    if 'url' in photo:
        try:
            # Extract public_id from URL
            # Cloudinary URL format: https://res.cloudinary.com/{cloud_name}/image/upload/v{version}/{public_id}.{format}
            url_parts = photo['url'].split('/')
            if 'photofun' in url_parts:
                # Get the public_id part (everything after upload/)
                upload_index = url_parts.index('upload')
                public_id_with_ext = '/'.join(url_parts[upload_index + 2:])  # Skip version number
                public_id = public_id_with_ext.rsplit('.', 1)[0]  # Remove extension
                cloudinary.uploader.destroy(public_id)
        except Exception as e:
            print(f"Failed to delete from Cloudinary: {e}")
            # Continue anyway to delete from database

    # Delete original from Cloudinary if it exists
    if 'original_url' in photo:
        try:
            url_parts = photo['original_url'].split('/')
            if 'photofun' in url_parts:
                upload_index = url_parts.index('upload')
                public_id_with_ext = '/'.join(url_parts[upload_index + 2:])
                public_id = public_id_with_ext.rsplit('.', 1)[0]
                cloudinary.uploader.destroy(public_id)
        except Exception as e:
            print(f"Failed to delete original from Cloudinary: {e}")

    # Delete associated votes
    mongo.db.votes.delete_many({'photo_id': photo_id})

    # Delete photo from database
    mongo.db.photos.delete_one({'_id': ObjectId(photo_id)})

    return jsonify({'success': True})

# Add this route after your existing routes

@app.route('/session/<session_id>/compare')
def compare_photos(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    session_doc = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})
    if not session_doc:
        flash('Adventure not found!')
        return redirect(url_for('home'))
    
    # Get all challenges with their photos
    challenges = list(mongo.db.challenges.find({'session_id': session_id}).sort('hour', 1))
    
    # Get all photos for this session, grouped by challenge
    challenge_photos = {}
    for challenge in challenges:
        challenge_id_str = str(challenge['_id'])
        # Find photos that have this challenge in their challenge_ids array
        photos = list(mongo.db.photos.find({
            'session_id': session_id,
            'challenge_ids': challenge_id_str
        }))
        # Also check for old schema photos
        old_photos = list(mongo.db.photos.find({
            'session_id': session_id,
            'challenge_id': challenge_id_str
        }))
        # Combine and deduplicate
        all_photos = {str(p['_id']): p for p in photos + old_photos}
        challenge_photos[challenge_id_str] = list(all_photos.values())
    
    return render_template('compare_photos.html',
                         session=session_doc,
                         challenges=challenges,
                         challenge_photos=challenge_photos,
                         session_id=session_id)

@app.route('/vote', methods=['POST'])
@csrf.exempt 
def vote_photo():
    photo_id = request.form['photo_id']
    rating = int(request.form['rating'])
    voter_id = session['user_id']
    
    # Remove any existing vote from this user for this photo
    mongo.db.votes.delete_many({
        'photo_id': photo_id,
        'voter_id': voter_id
    })
    
    # Add new vote
    vote_doc = {
        'photo_id': photo_id,
        'voter_id': voter_id,
        'voter_name': session['username'],
        'rating': rating,
        'voted_at': datetime.now()
    }
    mongo.db.votes.insert_one(vote_doc)
    
    # Calculate average rating for this photo
    votes = list(mongo.db.votes.find({'photo_id': photo_id}))
    avg_rating = sum(vote['rating'] for vote in votes) / len(votes) if votes else 0
    total_votes = len(votes)
    
    return jsonify({
        'success': True,
        'average_rating': round(avg_rating, 1),
        'total_votes': total_votes
    })

@app.route('/session/<session_id>/results')
def session_results(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    session_doc = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})
    challenges = list(mongo.db.challenges.find({'session_id': session_id}).sort('hour', 1))
    
    # Get photos with their vote statistics
    results = {}
    for challenge in challenges:
        challenge_id_str = str(challenge['_id'])
        # Find photos that have this challenge in their challenge_ids array
        photos = list(mongo.db.photos.find({
            'session_id': session_id,
            'challenge_ids': challenge_id_str
        }))
        # Also check for old schema photos
        old_photos = list(mongo.db.photos.find({
            'session_id': session_id,
            'challenge_id': challenge_id_str
        }))
        # Combine and deduplicate
        all_photos_dict = {str(p['_id']): p for p in photos + old_photos}
        photos = list(all_photos_dict.values())

        # Add vote stats to each photo
        for photo in photos:
            votes = list(mongo.db.votes.find({'photo_id': str(photo['_id'])}))
            photo['avg_rating'] = sum(vote['rating'] for vote in votes) / len(votes) if votes else 0
            photo['total_votes'] = len(votes)
            photo['votes'] = votes

        # Sort photos by rating
        photos.sort(key=lambda x: x['avg_rating'], reverse=True)
        results[challenge_id_str] = photos
    
    return render_template('session_results.html',
                         session=session_doc,
                         challenges=challenges,
                         results=results,
                         session_id=session_id)


# Web Push Notification API Routes
@app.route('/api/vapid-public-key')
def vapid_public_key():
    return jsonify({
        'publicKey': os.getenv('VAPID_PUBLIC_KEY', 'BG1n8WOJOZgp4dALDNHFRVo9Xq8fWx2FxOOKtqp9w1LGJW8_M9vALJ5k2ZJL3cY1N5N5Y9Q1Q6qF8Q3F7N1S8N4')
    })

@app.route('/api/subscribe', methods=['POST'])
@limiter.limit("10 per minute")
def subscribe():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    subscription_data = request.get_json()

    # Store subscription in database
    subscription_doc = {
        'user_id': session['user_id'],
        'username': session['username'],
        'subscription': subscription_data,
        'created_at': datetime.now()
    }

    # Remove any existing subscription for this user
    mongo.db.subscriptions.delete_many({'user_id': session['user_id']})
    mongo.db.subscriptions.insert_one(subscription_doc)

    return jsonify({'success': True})

def send_notification_to_user(user_id, title, body, data=None):
    """Send push notification to a specific user"""
    try:
        subscription_doc = mongo.db.subscriptions.find_one({'user_id': user_id})
        if not subscription_doc:
            return False

        payload = {
            'title': title,
            'body': body,
            'primaryKey': data.get('primary_key', 1) if data else 1
        }

        webpush(
            subscription_info=subscription_doc['subscription'],
            data=json.dumps(payload),
            vapid_private_key=os.getenv('VAPID_PRIVATE_KEY'),
            vapid_claims={
                "sub": os.getenv('VAPID_EMAIL', 'mailto:your-email@example.com')
            }
        )
        return True
    except WebPushException as ex:
        print(f"Push notification failed: {ex}")
        return False

def send_notification_to_session(session_id, title, body, exclude_user_id=None):
    """Send push notification to all users in a session"""
    try:
        # Get all participants in the session
        session_doc = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})
        if not session_doc:
            return

        participants = session_doc.get('participants', [])
        for participant_id in participants:
            if exclude_user_id and participant_id == exclude_user_id:
                continue
            send_notification_to_user(participant_id, title, body)
    except Exception as ex:
        print(f"Session notification failed: {ex}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    #app.run(debug=True, host="localhost", port=8080, threaded=True)
    app.run(debug=False, host="0.0.0.0", port=port, threaded=True)
