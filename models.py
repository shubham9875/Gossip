from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    google_id = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    profile_picture = db.Column(db.String(200))
    login_count = db.Column(db.Integer, default=0, nullable=False)
    
    # Add relationships for friends
    friends = db.relationship('User',
        secondary='friendship',
        primaryjoin=db.and_(id == Friendship.user_id, Friendship.status == 'accepted'),
        secondaryjoin=db.and_(id == Friendship.friend_id, Friendship.status == 'accepted'),
        backref=db.backref('friend_of', lazy='dynamic'),
        lazy='dynamic',
        viewonly=True
    )

    friend_requests_sent = db.relationship('Friendship',
        foreign_keys=[Friendship.user_id],
        backref=db.backref('sender', lazy=True),
        lazy='dynamic'
    )

    friend_requests_received = db.relationship('Friendship',
        foreign_keys=[Friendship.friend_id],
        backref=db.backref('receiver', lazy=True),
        lazy='dynamic'
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        return False

    def update_login_stats(self):
        self.last_login = datetime.utcnow()
        if self.login_count is None:
            self.login_count = 0
        self.login_count += 1
        db.session.commit()

    def send_friend_request(self, friend):
        if friend.id == self.id:
            return False, "You can't add yourself as a friend"
        
        existing = Friendship.query.filter(
            ((Friendship.user_id == self.id) & (Friendship.friend_id == friend.id)) |
            ((Friendship.user_id == friend.id) & (Friendship.friend_id == self.id))
        ).first()
        
        if existing:
            if existing.status == 'accepted':
                return False, "Already friends"
            elif existing.status == 'pending':
                return False, "Friend request already sent"
            
        friendship = Friendship(user_id=self.id, friend_id=friend.id)
        db.session.add(friendship)
        db.session.commit()
        return True, "Friend request sent"

    def accept_friend_request(self, friendship_id):
        friendship = Friendship.query.get(friendship_id)
        if not friendship or friendship.friend_id != self.id:
            return False, "Invalid friend request"
        
        # Accept the original request
        friendship.status = 'accepted'
        
        # Create reverse friendship
        reverse_friendship = Friendship.query.filter_by(
            user_id=friendship.friend_id,
            friend_id=friendship.user_id
        ).first()
        
        if not reverse_friendship:
            reverse_friendship = Friendship(
                user_id=friendship.friend_id,
                friend_id=friendship.user_id,
                status='accepted'
            )
            db.session.add(reverse_friendship)
        else:
            reverse_friendship.status = 'accepted'
        
        db.session.commit()
        return True, "Friend request accepted"

    def reject_friend_request(self, friendship_id):
        friendship = Friendship.query.get(friendship_id)
        if not friendship or friendship.friend_id != self.id:
            return False, "Invalid friend request"
        
        friendship.status = 'rejected'
        db.session.commit()
        return True, "Friend request rejected"

    def get_chat_messages(self, friend_id, limit=50):
        # Check if they are friends
        friendship = Friendship.query.filter(
            ((Friendship.user_id == self.id) & (Friendship.friend_id == friend_id)) |
            ((Friendship.user_id == friend_id) & (Friendship.friend_id == self.id)),
            Friendship.status == 'accepted'
        ).first()
        
        if not friendship:
            return []
            
        return Message.query.filter(
            ((Message.sender_id == self.id) & (Message.receiver_id == friend_id)) |
            ((Message.sender_id == friend_id) & (Message.receiver_id == self.id))
        ).order_by(Message.created_at.desc()).limit(limit).all()

    def send_message(self, receiver_id, content):
        # Check if they are friends
        friendship = Friendship.query.filter(
            ((Friendship.user_id == self.id) & (Friendship.friend_id == receiver_id)) |
            ((Friendship.user_id == receiver_id) & (Friendship.friend_id == self.id)),
            Friendship.status == 'accepted'
        ).first()
        
        if not friendship:
            return None
            
        message = Message(sender_id=self.id, receiver_id=receiver_id, content=content)
        db.session.add(message)
        db.session.commit()
        return message

    def delete_chat_messages(self, friend_id):
        # Delete all messages between the current user and friend
        Message.query.filter(
            ((Message.sender_id == self.id) & (Message.receiver_id == friend_id)) |
            ((Message.sender_id == friend_id) & (Message.receiver_id == self.id))
        ).delete()
        db.session.commit()
        return True

    def delete_message(self, message_id):
        message = Message.query.get(message_id)
        if not message:
            return False, "Message not found"
            
        # Only allow deleting if user is the sender
        if message.sender_id != self.id:
            return False, "Not authorized to delete this message"
            
        db.session.delete(message)
        db.session.commit()
        return True, "Message deleted"

    def get_friend_count(self):
        return Friendship.query.filter(
            ((Friendship.user_id == self.id) | (Friendship.friend_id == self.id)) &
            (Friendship.status == 'accepted')
        ).count() // 2  # Divide by 2 since each friendship is counted twice

    def get_message_count(self):
        return Message.query.filter(
            (Message.sender_id == self.id) | (Message.receiver_id == self.id)
        ).count()
    
    def get_days_active(self):
        if not self.last_login:
            return 0
        delta = datetime.utcnow() - self.created_at
        return delta.days

    @staticmethod
    def get_or_create_google_user(google_id, name, email, profile_picture=None):
        user = User.query.filter_by(google_id=google_id).first()
        if not user:
            user = User.query.filter_by(email=email).first()
            if user:
                # Link existing account with Google
                user.google_id = google_id
                user.profile_picture = profile_picture
            else:
                # Create new user
                user = User(
                    google_id=google_id,
                    name=name,
                    email=email,
                    profile_picture=profile_picture,
                    login_count=0
                )
                db.session.add(user)
        
        user.update_login_stats()
        return user

    def __repr__(self):
        return f'<User {self.email}>'
