from datetime import datetime
from bson.objectid import ObjectId

class PhotoSession:
    def __init__(self, name, start_time, created_by, duration_hours=8):
        self.name = name
        self.start_time = start_time
        self.duration_hours = duration_hours
        self.created_by = created_by
        self.created_at = datetime.now()
    
    def to_dict(self):
        return {
            'name': self.name,
            'start_time': self.start_time,
            'duration_hours': self.duration_hours,
            'created_by': self.created_by,
            'created_at': self.created_at
        }

class Challenge:
    def __init__(self, session_id, hour, title, description):
        self.session_id = session_id
        self.hour = hour  # 1, 2, 3, etc.
        self.title = title
        self.description = description
    
    def to_dict(self):
        return {
            'session_id': self.session_id,
            'hour': self.hour,
            'title': self.title,
            'description': self.description
        }

class Photo:
    def __init__(self, session_id, uploader_id, uploader_name, filename, challenge_id=None):
        self.session_id = session_id
        self.uploader_id = uploader_id
        self.uploader_name = uploader_name
        self.filename = filename
        self.challenge_id = challenge_id
        self.uploaded_at = datetime.now()
    
    def to_dict(self):
        return {
            'session_id': self.session_id,
            'uploader_id': self.uploader_id,
            'uploader_name': self.uploader_name,
            'filename': self.filename,
            'challenge_id': self.challenge_id,
            'uploaded_at': self.uploaded_at
        }
