from flask import Flask, render_template, url_for, redirect, session, request, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from models import db, User, Message, Friendship
import os
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = 'dev-secret-key-123'  # Development key, change in production

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flask_tutorial.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Add custom filters
@app.template_filter('md5')
def md5_filter(s):
    return hashlib.md5(s.lower().encode()).hexdigest()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            user.update_login_stats()
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))

        user = User(name=name, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash('Account created successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('signup.html')

@app.route('/profile')
@login_required
def profile():
    days_member = (datetime.utcnow() - current_user.created_at).days
    login_count = current_user.login_count or 0
    return render_template('profile.html', days_member=days_member, login_count=login_count)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        # Verify current password
        current_password = request.form.get('current_password')
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('edit_profile'))

        # Update name
        name = request.form.get('name')
        if name:
            current_user.name = name

        # Update email
        email = request.form.get('email')
        if email != current_user.email:
            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'error')
                return redirect(url_for('edit_profile'))
            current_user.email = email

        # Update profile picture
        profile_picture = request.form.get('profile_picture')
        current_user.profile_picture = profile_picture if profile_picture else None

        # Update password
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if new_password:
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return redirect(url_for('edit_profile'))
            current_user.set_password(new_password)

        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_profile.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/friends')
@login_required
def friends():
    # Get all friends from both directions
    friends = User.query.join(Friendship, db.or_(
        db.and_(Friendship.user_id == current_user.id, Friendship.friend_id == User.id),
        db.and_(Friendship.friend_id == current_user.id, Friendship.user_id == User.id)
    )).filter(Friendship.status == 'accepted').all()
    
    # Get pending friend requests
    friend_requests = current_user.friend_requests_received.filter_by(status='pending').all()
    return render_template('friends.html', friends=friends, friend_requests=friend_requests)

@app.route('/friends/search')
@login_required
def search_friends():
    query = request.args.get('q', '')
    if query:
        users = User.query.filter(
            User.id != current_user.id,
            User.name.ilike(f'%{query}%')
        ).limit(10).all()
    else:
        users = []
    return render_template('search_friends.html', users=users, query=query)

@app.route('/friends/add/<int:user_id>', methods=['POST'])
@login_required
def add_friend(user_id):
    friend = User.query.get_or_404(user_id)
    success, message = current_user.send_friend_request(friend)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('friends'))

@app.route('/friends/accept/<int:friendship_id>', methods=['POST'])
@login_required
def accept_friend(friendship_id):
    success, message = current_user.accept_friend_request(friendship_id)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('friends'))

@app.route('/friends/reject/<int:friendship_id>', methods=['POST'])
@login_required
def reject_friend(friendship_id):
    success, message = current_user.reject_friend_request(friendship_id)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('friends'))

@app.route('/chats')
@app.route('/chats/<int:friend_id>')
@login_required
def chats(friend_id=None):
    # Get all friends
    friends = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) | (Friendship.friend_id == current_user.id)) &
        (Friendship.status == 'accepted')
    ).all()
    
    # Convert to list of friend users
    friend_users = []
    for friendship in friends:
        friend_user = User.query.get(
            friendship.friend_id if friendship.user_id == current_user.id 
            else friendship.user_id
        )
        if friend_user:
            friend_users.append(friend_user)
    
    # Get active friend if friend_id is provided
    active_friend = None
    messages = []
    if friend_id:
        active_friend = User.query.get_or_404(friend_id)
        # Check if they are friends
        friendship = Friendship.query.filter(
            ((Friendship.user_id == current_user.id) & (Friendship.friend_id == friend_id)) |
            ((Friendship.user_id == friend_id) & (Friendship.friend_id == current_user.id)),
            Friendship.status == 'accepted'
        ).first()
        
        if not friendship:
            flash('You can only chat with your friends', 'error')
            return redirect(url_for('chats'))
            
        # Get messages between current user and active friend
        messages = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == friend_id)) |
            ((Message.sender_id == friend_id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.created_at).all()
    
    # Get last message for each friend
    friend_messages = {}
    for friend in friend_users:
        last_message = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == friend.id)) |
            ((Message.sender_id == friend.id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.created_at.desc()).first()
        friend_messages[friend.id] = last_message

    return render_template(
        'chats.html',
        friends=friend_users,
        active_friend=active_friend,
        messages=messages,
        friend_messages=friend_messages
    )

@app.route('/send_message/<int:friend_id>', methods=['POST'])
@login_required
def send_message(friend_id):
    friend = User.query.get_or_404(friend_id)
    
    # Check if they are friends
    friendship = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == current_user.id)),
        Friendship.status == 'accepted'
    ).first()
    
    if not friendship:
        flash('You can only send messages to your friends', 'error')
        return redirect(url_for('chats'))
    
    content = request.form.get('message')
    if not content:
        flash('Message cannot be empty', 'error')
        return redirect(url_for('chats', friend_id=friend_id))
    
    # Create new message
    message = Message(
        content=content,
        sender_id=current_user.id,
        receiver_id=friend_id
    )
    db.session.add(message)
    
    try:
        db.session.commit()
        flash('Message sent successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error sending message', 'error')
        print(f"Error sending message: {e}")
    
    return redirect(url_for('chats', friend_id=friend_id))

@app.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    
    if message.sender_id != current_user.id:
        flash('You can only delete your own messages', 'error')
        return redirect(url_for('chats', friend_id=message.receiver_id))
    
    friend_id = message.receiver_id
    
    try:
        db.session.delete(message)
        db.session.commit()
        flash('Message deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting message', 'error')
        print(f"Error deleting message: {e}")
    
    return redirect(url_for('chats', friend_id=friend_id))

@app.route('/delete_chat/<int:friend_id>', methods=['POST'])
@login_required
def delete_chat(friend_id):
    friend = User.query.get_or_404(friend_id)
    # Check if they are friends
    friendship = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == current_user.id)),
        Friendship.status == 'accepted'
    ).first()
    
    if not friendship:
        return {'error': 'Not friends'}, 403
        
    current_user.delete_chat_messages(friend_id)
    flash('Chat history deleted successfully', 'success')
    return redirect(url_for('chats'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = current_user
    # Delete user's messages
    Message.query.filter((Message.sender_id == user.id) | (Message.receiver_id == user.id)).delete()
    # Delete user's chats
    Friendship.query.filter((Friendship.user_id == user.id) | (Friendship.friend_id == user.id)).delete()
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    logout_user()
    flash('Your account has been deleted successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/get_messages/<int:friend_id>')
@login_required
def get_messages(friend_id):
    friend = User.query.get_or_404(friend_id)
    messages = current_user.get_chat_messages(friend_id)
    return jsonify([{
        'id': message.id,
        'content': message.content,
        'created_at': message.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'sender_name': message.sender.name,
        'is_sender': message.sender_id == current_user.id
    } for message in messages])

@app.route('/search_users', methods=['GET'])
@login_required
def search_users():
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify([])
    
    try:
        # Search for users whose name or email contains the query
        users = User.query.filter(
            (User.id != current_user.id) &  # Exclude current user
            (
                User.name.ilike(f'%{query}%') |  # Case-insensitive name search
                User.email.ilike(f'%{query}%')    # Case-insensitive email search
            )
        ).limit(10).all()  # Limit to 10 results
        
        # Get friendship status for each user
        results = []
        for user in users:
            friendship = Friendship.query.filter(
                ((Friendship.user_id == current_user.id) & (Friendship.friend_id == user.id)) |
                ((Friendship.user_id == user.id) & (Friendship.friend_id == current_user.id))
            ).first()
            
            status = friendship.status if friendship else 'none'
            
            results.append({
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'profile_picture': user.profile_picture or f'https://www.gravatar.com/avatar/{md5(user.email.lower().encode()).hexdigest()}?s=40&d=identicon',
                'friendship_status': status
            })
        
        return jsonify(results)
        
    except Exception as e:
        print(f"Search error: {e}")
        return jsonify({'error': 'An error occurred while searching'}), 500

def init_db():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5002
    init_db()  # Initialize database tables
    app.run(debug=True, host='0.0.0.0', port=port)
