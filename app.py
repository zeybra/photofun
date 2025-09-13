from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_pymongo import PyMongo
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
import os
import uuid
import time

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-later'  # Change this!
app.config["MONGO_URI"] = "mongodb://localhost:27017/photo_challenge"

# File upload config
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

mongo = PyMongo(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

# Simple auth routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        if username:  # Super simple - just check if username exists
            session['user_id'] = str(uuid.uuid4())  # Generate simple user ID
            session['username'] = username
            return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Session management routes
@app.route('/create-session', methods=['GET', 'POST'])
def create_session():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        session_name = request.form['session_name']
        start_time = datetime.now()  # Start immediately for now
        duration_hours = int(request.form.get('duration_hours', 8))
        
        # Create session in MongoDB
        session_doc = {
            'name': session_name,
            'start_time': start_time,
            'duration_hours': duration_hours,
            'created_by': session['user_id'],
            'created_by_name': session['username'],
            'created_at': datetime.now(),
            'participants': [session['user_id']]
        }
        
        result = mongo.db.sessions.insert_one(session_doc)
        session_id = str(result.inserted_id)
        
        # Create default challenges for this session
        create_default_challenges(session_id, duration_hours)
        
        flash(f'Adventure "{session_name}" created successfully!')
        return redirect(url_for('session_view', session_id=session_id))
    
    return render_template('create_session.html')

@app.route('/join-session')
def join_session():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('join_session.html')

@app.route('/session/<session_id>')
def session_view(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get session from database
    session_doc = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})
    if not session_doc:
        flash('Adventure not found!')
        return redirect(url_for('home'))
    
    # Get challenges for this session
    challenges = list(mongo.db.challenges.find({'session_id': session_id}).sort('hour', 1))
    
    # Calculate current challenge
    start_time = session_doc['start_time']
    current_time = datetime.now()
    hours_elapsed = (current_time - start_time).total_seconds() / 3600
    current_challenge_hour = int(hours_elapsed) + 1
    
    return render_template('session_view.html', 
                         session=session_doc, 
                         challenges=challenges,
                         current_challenge_hour=current_challenge_hour,
                         session_id=session_id)

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
                # Create unique filename
                timestamp = str(int(time.time()))
                filename = secure_filename(f"{timestamp}_{session['username']}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Save to database
                photo_doc = {
                    'session_id': session_id,
                    'uploader_id': session['user_id'],
                    'uploader_name': session['username'],
                    'filename': filename,
                    'challenge_id': None,  # Will be assigned later
                    'uploaded_at': datetime.now()
                }
                mongo.db.photos.insert_one(photo_doc)
                uploaded_count += 1
        
        flash(f'Successfully uploaded {uploaded_count} photos!')
        return redirect(url_for('categorize_photos', session_id=session_id))
    
    # Get challenges for this session
    challenges = list(mongo.db.challenges.find({'session_id': session_id}).sort('hour', 1))
    
    return render_template('upload_photos.html', 
                         session=session_doc, 
                         challenges=challenges,
                         session_id=session_id)

@app.route('/session/<session_id>/categorize')
def categorize_photos(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get uncategorized photos for current user
    photos = list(mongo.db.photos.find({
        'session_id': session_id,
        'uploader_id': session['user_id'],
        'challenge_id': None
    }))
    
    challenges = list(mongo.db.challenges.find({'session_id': session_id}).sort('hour', 1))
    session_doc = mongo.db.sessions.find_one({'_id': ObjectId(session_id)})
    
    return render_template('categorize_photos.html',
                         photos=photos,
                         challenges=challenges,
                         session=session_doc,
                         session_id=session_id)

@app.route('/assign-photo', methods=['POST'])
def assign_photo():
    photo_id = request.form['photo_id']
    challenge_id = request.form['challenge_id']
    
    mongo.db.photos.update_one(
        {'_id': ObjectId(photo_id)},
        {'$set': {'challenge_id': challenge_id}}
    )
    
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
        photos = list(mongo.db.photos.find({
            'session_id': session_id,
            'challenge_id': str(challenge['_id'])
        }))
        challenge_photos[str(challenge['_id'])] = photos
    
    return render_template('compare_photos.html',
                         session=session_doc,
                         challenges=challenges,
                         challenge_photos=challenge_photos,
                         session_id=session_id)

@app.route('/vote', methods=['POST'])
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
        photos = list(mongo.db.photos.find({
            'session_id': session_id,
            'challenge_id': str(challenge['_id'])
        }))
        
        # Add vote stats to each photo
        for photo in photos:
            votes = list(mongo.db.votes.find({'photo_id': str(photo['_id'])}))
            photo['avg_rating'] = sum(vote['rating'] for vote in votes) / len(votes) if votes else 0
            photo['total_votes'] = len(votes)
            photo['votes'] = votes
        
        # Sort photos by rating
        photos.sort(key=lambda x: x['avg_rating'], reverse=True)
        results[str(challenge['_id'])] = photos
    
    return render_template('session_results.html',
                         session=session_doc,
                         challenges=challenges,
                         results=results,
                         session_id=session_id)

def create_default_challenges(session_id, duration_hours):
    """Create default Prague challenges"""
    prague_challenges = [
        {"title": "Unique Czech Discovery", "description": "Find something uniquely Czech that tourists usually miss"},
        {"title": "Castle View Alternative", "description": "Capture the best castle view that isn't the obvious tourist spot"}, 
        {"title": "Old Meets New", "description": "Something that shows the contrast between old and new Prague"},
        {"title": "Architectural Story", "description": "Find a door, window, or building detail that tells a story"},
        {"title": "Hidden Street Art", "description": "Discover street art or graffiti that caught your eye"},
        {"title": "Local Life", "description": "Capture a local person doing something traditionally Prague"},
        {"title": "Fairy Tale Architecture", "description": "Architecture that looks like it belongs in a fairy tale"},
        {"title": "Unexpected Perspective", "description": "A view or angle of Prague that surprises you"},
        {"title": "Cultural Detail", "description": "A small detail that represents Czech culture"},
        {"title": "Final Adventure", "description": "Your favorite discovery from the entire adventure"}
    ]
    
    # Create challenges up to duration_hours
    challenges_to_create = min(len(prague_challenges), duration_hours)
    
    for hour in range(1, challenges_to_create + 1):
        challenge_doc = {
            'session_id': session_id,
            'hour': hour,
            'title': prague_challenges[hour-1]['title'],
            'description': prague_challenges[hour-1]['description']
        }
        mongo.db.challenges.insert_one(challenge_doc)

if __name__ == '__main__':
    app.run(debug=True)
