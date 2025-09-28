# Photo Challenge Templates
# Add new challenge sets here for different cities/themes

CHALLENGE_SETS = {
    'prague': {
        'name': 'Prague Adventure',
        'description': 'Discover the hidden gems of Prague',
        'challenges': [
            {
                "title": "Unique Czech Discovery",
                "description": "Find something uniquely Czech that tourists usually miss"
            },
            {
                "title": "Castle View Alternative",
                "description": "Capture the best castle view that isn't the obvious tourist spot"
            },
            {
                "title": "Old Meets New",
                "description": "Something that shows the contrast between old and new Prague"
            },
            {
                "title": "Architectural Story",
                "description": "Find a door, window, or building detail that tells a story"
            },
            {
                "title": "Hidden Street Art",
                "description": "Discover street art or graffiti that caught your eye"
            },
            {
                "title": "Local Life",
                "description": "Capture a local person doing something traditionally Prague"
            },
            {
                "title": "Fairy Tale Architecture",
                "description": "Architecture that looks like it belongs in a fairy tale"
            },
            {
                "title": "Unexpected Perspective",
                "description": "A view or angle of Prague that surprises you"
            },
            {
                "title": "Cultural Detail",
                "description": "A small detail that represents Czech culture"
            },
            {
                "title": "Final Adventure",
                "description": "Your favorite discovery from the entire adventure"
            }
        ]
    },

    'stockholm': {
        'name': 'Stockholm Explorer',
        'description': 'Navigate the archipelago city',
        'challenges': [
            {
                "title": "Island Hopping",
                "description": "Capture the essence of Stockholm's island geography"
            },
            {
                "title": "Royal Discovery",
                "description": "Find royal history beyond the obvious palace"
            },
            {
                "title": "Nordic Design",
                "description": "Spot distinctive Scandinavian design in everyday life"
            },
            {
                "title": "Water Reflection",
                "description": "Use Stockholm's abundant water for a perfect reflection shot"
            },
            {
                "title": "Gamla Stan Secret",
                "description": "Discover a hidden corner of the Old Town"
            },
            {
                "title": "Modern Stockholm",
                "description": "Capture the contemporary side of the city"
            },
            {
                "title": "Local Fika",
                "description": "Document Swedish coffee culture in action"
            },
            {
                "title": "Colorful Stockholm",
                "description": "Find the most colorful scene in the city"
            },
            {
                "title": "Winter Wonder",
                "description": "Embrace the Nordic winter atmosphere"
            },
            {
                "title": "Stockholm Soul",
                "description": "One shot that captures the spirit of Stockholm"
            }
        ]
    },

    'rome': {
        'name': 'Roman Quest',
        'description': 'Explore the eternal city',
        'challenges': [
            {
                "title": "Ancient Meets Modern",
                "description": "Find where 2000+ year old Rome meets today"
            },
            {
                "title": "Hidden Ruins",
                "description": "Discover ancient remains off the tourist trail"
            },
            {
                "title": "Roman Daily Life",
                "description": "Capture how Romans live among their history"
            },
            {
                "title": "Fountain Magic",
                "description": "Find a beautiful fountain beyond the Trevi"
            },
            {
                "title": "Artisan at Work",
                "description": "Document traditional Roman craftsmanship"
            },
            {
                "title": "Trastevere Character",
                "description": "Capture the authentic neighborhood vibe"
            },
            {
                "title": "Food Culture",
                "description": "Show the passion Romans have for food"
            },
            {
                "title": "Sacred Space",
                "description": "Find spiritual beauty in unexpected places"
            },
            {
                "title": "Golden Hour Rome",
                "description": "Use the perfect Roman light"
            },
            {
                "title": "Eternal City",
                "description": "One image that shows why Rome is eternal"
            }
        ]
    },

    'generic': {
        'name': 'Urban Explorer',
        'description': 'Discover any city like a local',
        'challenges': [
            {
                "title": "Hidden Gem",
                "description": "Find a place locals love but tourists miss"
            },
            {
                "title": "Street Art Story",
                "description": "Capture street art that tells a story"
            },
            {
                "title": "Local Gathering",
                "description": "Document where locals actually hang out"
            },
            {
                "title": "Architectural Detail",
                "description": "Find an interesting building detail that catches your eye"
            },
            {
                "title": "City Rhythm",
                "description": "Show the pace and energy of city life"
            },
            {
                "title": "Green Space",
                "description": "Find nature thriving in the urban environment"
            },
            {
                "title": "Cultural Contrast",
                "description": "Capture old and new, or different cultures meeting"
            },
            {
                "title": "Working Life",
                "description": "Show people going about their daily work"
            },
            {
                "title": "City at Night",
                "description": "Capture the city's after-dark personality"
            },
            {
                "title": "Your Discovery",
                "description": "The most surprising thing you found today"
            }
        ]
    }
}

def get_challenge_set(set_name):
    """Get a specific challenge set"""
    return CHALLENGE_SETS.get(set_name, CHALLENGE_SETS['generic'])

def get_available_sets():
    """Get list of all available challenge sets"""
    return {k: v['name'] for k, v in CHALLENGE_SETS.items()}

def create_challenges_for_session(session_id, challenge_set='prague', duration_hours=8):
    """Create challenges for a session"""
    from app import mongo
    from datetime import datetime

    challenge_data = get_challenge_set(challenge_set)
    challenges = challenge_data['challenges']

    # Create challenges up to duration_hours
    challenges_to_create = min(len(challenges), duration_hours)

    for hour in range(1, challenges_to_create + 1):
        challenge_doc = {
            'session_id': session_id,
            'hour': hour,
            'title': challenges[hour-1]['title'],
            'description': challenges[hour-1]['description'],
            'challenge_set': challenge_set
        }
        mongo.db.challenges.insert_one(challenge_doc)