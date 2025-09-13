from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_pymongo import PyMongo
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
import uuid

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
