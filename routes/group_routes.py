from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from markupsafe import escape
from datetime import datetime
import uuid
import os
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename
import uuid


def create_notification(username, message, notification_type="info"):
    """Create a notification for a user"""
    notifications.insert_one({
        "username": username,
        "message": message,
        "type": notification_type,
        "read": False,
        "timestamp": datetime.now()
    })

group_bp = Blueprint('groups', __name__)

# MongoDB connection (same as app.py)
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/daap_secdov")
client = MongoClient(MONGO_URI)
db = client["daap_secdov"]
groups = db["groups"]
group_messages = db["group_messages"]
group_invitations = db["group_invitations"]
users = db["users"]
notifications = db["notifications"]

# Import limiter from extensions module (avoids circular import with app.py)
from extensions import limiter



@group_bp.route('/create_group', methods=['POST'])
@limiter.limit("5 per hour")  # Prevents spam group creation
def create_group():
    """Create a new group"""
    if "username" not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('login'))
    
    # Sanitize group name to prevent XSS
    group_name = escape(request.form.get('group_name', '').strip())
    creator = session["username"]
    
    # Validate group name
    if not group_name:
        flash("Group name cannot be empty.", "error")
        return redirect(url_for('home'))
    
    if len(group_name) > 50:
        flash("Group name too long (max 50 characters).", "error")
        return redirect(url_for('home'))
    
    # Check for invalid characters
    invalid_chars = ['<', '>', '&', '"', "'"]
    if any(char in group_name for char in invalid_chars):
        flash("Group name contains invalid characters.", "error")
        return redirect(url_for('home'))
    
    # Generate unique group ID
    group_id = str(uuid.uuid4())
    
    # Create group
    groups.insert_one({
        "group_id": group_id,
        "name": group_name,
        "admin": creator,  # Original creator
        "admins": [creator],  # List of all admins
        "members": [creator],  # Creator auto-joins
        "invited": [],  # Pending invitations
        "created_at": datetime.now(),
        "member_join_times": {creator: datetime.now().isoformat()}
    })
    
    flash(f"Group '{group_name}' created successfully!", "success")
    return redirect(url_for('home'))


@group_bp.route('/invite_to_group', methods=['POST'])
@limiter.limit("20 per hour")  # Prevents invitation spam
def invite_to_group():
    """Invite a user to a group"""
    if "username" not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('login'))
    
    group_id = request.form.get('group_id')
    to_user = request.form.get('to_user')
    from_user = session["username"]
    
    group = groups.find_one({"group_id": group_id})
    
    if not group:
        flash("Group not found.", "error")
        return redirect(url_for('home'))
    
    # Check if user is a admin (only admins can invite)
    if from_user not in group.get("admins", []):
        flash("Only group admins can invite others.", "error")
        return redirect(url_for('home'))
    
    # Check if target user exists
    target_user = users.find_one({"username": to_user})
    if not target_user:
        #flash(f"User '{to_user}' not found.", "error")
        return redirect(url_for('home'))
    
    # Check if already a member
    if to_user in group.get("members", []):
        flash(f"{to_user} is already a member.", "info")
        return redirect(url_for('home'))
    
    # Check if already invited
    if to_user in group.get("invited", []):
        flash(f"{to_user} already has a pending invitation.", "info")
        return redirect(url_for('home'))
    
    # Add to invited list
    groups.update_one(
        {"group_id": group_id},
        {"$addToSet": {"invited": to_user}}
    )
    
    # Create invitation record
    group_invitations.insert_one({
        "group_id": group_id,
        "group_name": group.get("name"),
        "from_user": from_user,
        "to_user": to_user,
        "status": "pending",
        "timestamp": datetime.now()
    })
    
    flash(f"Invitation sent to {to_user}!", "success")
    return redirect(url_for('home'))


@group_bp.route('/respond_group_invitation', methods=['POST'])
@limiter.limit("20 per hour")  # Prevents spam accepting/rejecting invitations
def respond_group_invitation():
    """Accept or reject a group invitation"""
    if "username" not in session:
        return redirect(url_for('login'))
    
    group_id = request.form.get('group_id')
    action = request.form.get('action')
    username = session["username"]
    
    invitation = group_invitations.find_one({
        "group_id": group_id,
        "to_user": username,
        "status": "pending"
    })
    
    if not invitation:
        flash("Invitation not found or already responded to.", "error")
        return redirect(url_for('home'))
    
    group = groups.find_one({"group_id": group_id})
    
    if not group:
        flash("Group not found.", "error")
        return redirect(url_for('home'))
    
    if action == "accept":
        # Add user to members
        groups.update_one(
            {"group_id": group_id},
            {
                "$addToSet": {"members": username},
                "$pull": {"invited": username},
                "$set": {f"member_join_times.{username}": datetime.now().isoformat()}
            }
        )
        
        # Update invitation status
        group_invitations.update_one(
            {"_id": invitation["_id"]},
            {"$set": {"status": "accepted"}}
        )
        
        flash(f"You joined the group '{group['name']}'!", "success")
    
    elif action == "reject":
        # Remove from invited list
        groups.update_one(
            {"group_id": group_id},
            {"$pull": {"invited": username}}
        )
        
        # Update invitation status
        group_invitations.update_one(
            {"_id": invitation["_id"]},
            {"$set": {"status": "rejected"}}
        )
        
        flash(f"You rejected the invitation to '{group['name']}'.", "info")
    
    return redirect(url_for('home'))


@group_bp.route('/leave_group', methods=['POST'])
@limiter.limit("10 per hour")  # Prevents abuse of leaving groups repeatedly
def leave_group():
    """Leave a group"""
    if "username" not in session:
        return redirect(url_for('login'))
    
    group_id = request.form.get('group_id')
    username = session["username"]
    
    group = groups.find_one({"group_id": group_id})
    
    if not group:
        flash("Group not found.", "error")
        return redirect(url_for('home'))
    
    # Check if user is the only admin
    if username in group.get("admins", []) and len(group.get("admins", [])) == 1:
        flash("You are the only admin. Please assign another admin or delete the group.", "error")
        return redirect(url_for('home'))
    
    # Remove user from members and admins
    groups.update_one(
        {"group_id": group_id},
        {
            "$pull": {
                "members": username,
                "admins": username
            },
            "$unset": {f"member_join_times.{username}": ""}
        }
    )
    
    flash(f"You left the group '{group['name']}'.", "success")
    return redirect(url_for('home'))


@group_bp.route('/delete_group', methods=['POST'])
@limiter.limit("5 per hour")  # Prevents abuse of destructive group deletion
def delete_group():
    """Delete a group (admin only)"""
    if "username" not in session:
        return redirect(url_for('login'))
    
    group_id = request.form.get('group_id')
    username = session["username"]
    
    group = groups.find_one({"group_id": group_id})
    
    if not group:
        flash("Group not found.", "error")
        return redirect(url_for('home'))
    
    # Check if user is admin
    if username not in group.get("admins", []):
        flash("Only admins can delete groups.", "error")
        return redirect(url_for('home'))
    
    group_name = group.get("name")
    
    # Notify all members (except the deleter)
    for member in group.get("members", []):
        if member != username:
            create_notification(
                member,
                f"The group '{group_name}' has been deleted.",
                "warning"
            )
    
    # Delete group and all related data
    groups.delete_one({"group_id": group_id})
    group_messages.delete_many({"group_id": group_id})
    group_invitations.delete_many({"group_id": group_id})
    
    flash(f"Group '{group_name}' has been deleted.", "success")
    return redirect(url_for('home'))


@group_bp.route('/send_group_message', methods=['POST'])
@limiter.limit("30 per minute")  # Prevents message spam while allowing normal conversation
def send_group_message():
    """Send a message to a group"""
    
    group_id = request.form.get('group_id')

    if "username" not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('groups.group_chat', group_id=group_id))
    
    sender = session["username"]
    # Sanitize message content to prevent XSS attacks
    content = escape(request.form.get('content', '').strip())
    filename = None
    
    group = groups.find_one({"group_id": group_id})
    
    if not group:
        flash("Group not found.", "error")
        return redirect(url_for('home'))
    
    # Check if user is a member
    if sender not in group.get("members", []):
        flash("You must be a member to send messages.", "error")
        return redirect(url_for('home'))
    
    # Handle file upload
    file = request.files.get('file')
    
    if file and file.filename:
        # Import necessary functions at the top of the file
        from werkzeug.utils import secure_filename
        import uuid
        
        # Check if file type is allowed
        ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip'}
        
        def allowed_file(filename):
            return '.' in filename and \
                   filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
        
        if allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            
            # Generate unique filename
            unique_id = str(uuid.uuid4())
            filename = f"{unique_id}_{original_filename}"
            
            # Save file
            UPLOAD_FOLDER = 'uploads'
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            
            # Set default content if none provided
            if not content:
                content = f"File shared: {original_filename}"
        elif file.filename != '':
            flash("Invalid file type. Allowed extensions: txt, pdf, png, jpg, jpeg, gif, zip.", "error")
            return redirect(url_for('groups.group_chat', group_id=group_id))
    
    # Check if both content and file are empty
    if not content and not filename:
        flash("Cannot send an empty message or file.", "error")
        return redirect(url_for('groups.group_chat', group_id=group_id))
    
    # Insert message with optional filename
    group_messages.insert_one({
        "group_id": group_id,
        "group_name": group.get("name"),
        "sender": sender,
        "content": content,
        "filename": filename,
        "timestamp": datetime.now()
    })
    
    flash("Message sent to group!", "success")
    return redirect(url_for('groups.group_chat', group_id=group_id))

@group_bp.route('/delete_group_message/<message_id>', methods=['POST'])
@limiter.limit("30 per minute")  # Prevents deletion spam (consistent with delete_message)
def delete_group_message(message_id):

    if "username" not in session:
        flash("You must be logged in to delete messages.", "error")
        return redirect(url_for('login'))
    
    sender = session["username"]
    redirect_group_id = None 
    
    try:
        obj_id = ObjectId(message_id)
        
        message_to_delete = group_messages.find_one({
            "_id": obj_id,
            "sender": sender
        })

        if message_to_delete:
            redirect_group_id = message_to_delete['group_id']
            
            result = group_messages.delete_one({"_id": obj_id, "sender": sender})

            if result.deleted_count == 1:
                flash("Group message deleted.", "success")
            # If deleted_count is 0, the message was likely already deleted or sender didn't match.
        else:
            flash("Message not found or you don't have permission to delete it.", "error")
            
    except Exception as e:
        print(f"Error deleting group message: {e}")
        flash("Invalid message ID.", "error")
    
    if redirect_group_id:
        return redirect(url_for('groups.group_chat', group_id=redirect_group_id))
    else:
        return redirect(url_for('home'))



@group_bp.route('/manage_group/<group_id>')
def manage_group(group_id):
    """Group management page"""
    if "username" not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('login'))
    
    username = session["username"]
    group = groups.find_one({"group_id": group_id})
    
    if not group:
        flash("Group not found.", "error")
        return redirect(url_for('home'))
    
    # Check if user is a member
    if username not in group.get("members", []):
        flash("You must be a member to view this group.", "error")
        return redirect(url_for('home'))
    

    
    is_admin = username in group.get("admins", [])
    
    return render_template(
        'groups/manage.html',
        group=group,
        is_admin=is_admin,
        username=username
    )


@group_bp.route('/update_group_admin', methods=['POST'])
@limiter.limit("10 per hour")  # Prevents abuse of admin privilege changes
def update_group_admin():
    """Add or remove group admin (admin only)"""
    if "username" not in session:
        return redirect(url_for('login'))
    
    group_id = request.form.get('group_id')
    target_user = request.form.get('target_user')
    action = request.form.get('action')  # 'add' or 'remove'
    username = session["username"]
    
    group = groups.find_one({"group_id": group_id})
    
    if not group:
        flash("Group not found.", "error")
        return redirect(url_for('home'))
    
    # Check if requester is admin
    if username not in group.get("admins", []):
        flash("Only admins can modify admin list.", "error")
        return redirect(url_for('home'))
    
    # Check if target is a member
    if target_user not in group.get("members", []):
        flash("User must be a member of the group.", "error")
        return redirect(url_for('home'))
    
    if action == "add":
        groups.update_one(
            {"group_id": group_id},
            {"$addToSet": {"admins": target_user}}
        )
        flash(f"{target_user} is now an admin.", "success")
    
    elif action == "remove":
        # Prevent admins from removing other admins
        if target_user in group.get("admins", []) and target_user != username:
            flash("Admins cannot remove other admins.", "error")
            return redirect(url_for('groups.manage_group', group_id=group_id))
        
        # Allow self-demotion (user removing themselves as admin)
        if target_user == username:
            # Prevent removing last admin
            if len(group.get("admins", [])) == 1:
                flash("Cannot remove the last admin. Promote someone else first.", "error")
                return redirect(url_for('groups.manage_group', group_id=group_id))
            
            groups.update_one(
                {"group_id": group_id},
                {"$pull": {"admins": target_user}}
            )
            flash("You are no longer an admin.", "success")
        
    return redirect(url_for('groups.manage_group', group_id=group_id))

@group_bp.route('/group_chat/<group_id>')
def group_chat(group_id):
    """View and send messages in a group chat"""
    if "username" not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('login'))
    
    username = session["username"]
    group = groups.find_one({"group_id": group_id})
    
    if not group:
        flash("Group not found.", "error")
        return redirect(url_for('home'))
    
    # Check if user is a member
    if username not in group.get("members", []):
        flash("You must be a member to view this group.", "error")
        return redirect(url_for('home'))
    
    # Get user's join time
    join_time_str = group.get("member_join_times", {}).get(username)
    if join_time_str:
        join_time = datetime.fromisoformat(join_time_str)
        # Only show messages after user joined
        conversation = list(group_messages.find({
            "group_id": group_id,
            "timestamp": {"$gte": join_time}
        }).sort("timestamp", 1))
    else:
        conversation = []
    
    is_admin = username in group.get("admins", [])
    
    return render_template(
        'group_chat.html',
        username=username,
        group=group,
        conversation=conversation,
        is_admin=is_admin
    )

@group_bp.route('/remove_group_member', methods=['POST'])
@limiter.limit("10 per hour")  # Prevents abuse of member removal
def remove_group_member():
    """Remove a member from group (admin only)"""
    if "username" not in session:
        return redirect(url_for('login'))
    
    group_id = request.form.get('group_id')
    target_user = request.form.get('target_user')
    username = session["username"]
    
    group = groups.find_one({"group_id": group_id})
    
    if not group:
        flash("Group not found.", "error")
        return redirect(url_for('home'))
    
    # Check if requester is admin
    if username not in group.get("admins", []):
        flash("Only admins can remove members.", "error")
        return redirect(url_for('home'))
    
    # Cannot remove yourself this way
    if target_user == username:
        flash("Use 'Leave Group' to leave the group.", "error")
        return redirect(url_for('groups.manage_group', group_id=group_id))
    
    # Cannot remove other admins
    if target_user in group.get("admins", []):
        flash("Cannot remove other admins from the group.", "error")
        return redirect(url_for('groups.manage_group', group_id=group_id))
    
    group_name = group.get("name")
    
    # Remove user
    groups.update_one(
        {"group_id": group_id},
        {
            "$pull": {
                "members": target_user,
                "admins": target_user
            },
            "$unset": {f"member_join_times.{target_user}": ""}
        }
    )
    
    # Notify the removed user
    create_notification(
        target_user,
        f"You have been removed from the group '{group_name}'.",
        "warning"
    )
    
    flash(f"{target_user} has been removed from the group.", "success")
    return redirect(url_for('groups.manage_group', group_id=group_id))