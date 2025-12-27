# SERVER_ROUTES.py
# ================================================
# Add these routes to your Flask backend for the 
# desktop runner to work with emergentflow.io
# ================================================

from flask import Blueprint, request, jsonify, render_template_string, redirect
from functools import wraps
import jwt

runner_bp = Blueprint('runner', __name__)

# ================================================
# AUTH ENDPOINT - User logs in via browser
# ================================================

RUNNER_LOGIN_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>EmergentFlow Runner Login</title>
    <style>
        body {
            font-family: -apple-system, system-ui, sans-serif;
            background: #0f1419;
            color: #e7e9ea;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }
        .card {
            background: #1a1f26;
            border: 1px solid #2d3640;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            max-width: 400px;
        }
        h1 { margin: 0 0 8px; font-size: 24px; }
        p { color: #8b98a5; margin: 0 0 24px; }
        .btn {
            display: inline-block;
            background: #3b82f6;
            color: white;
            padding: 12px 32px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 500;
        }
        .btn:hover { background: #2563eb; }
        .success {
            color: #22c55e;
            font-size: 48px;
            margin-bottom: 16px;
        }
    </style>
</head>
<body>
    <div class="card">
        {% if success %}
            <div class="success">✓</div>
            <h1>Connected!</h1>
            <p>You can close this window and return to the Runner app.</p>
        {% elif logged_in %}
            <h1>Connect Runner</h1>
            <p>Allow EmergentFlow Runner to access your account?</p>
            <a href="{{ url_for('runner.runner_authorize') }}" class="btn">Authorize Runner</a>
        {% else %}
            <h1>Login Required</h1>
            <p>Please log in to connect the Runner app.</p>
            <a href="{{ url_for('auth.login', next='/auth/runner-login') }}" class="btn">Login</a>
        {% endif %}
    </div>
</body>
</html>
'''

@runner_bp.route('/auth/runner-login')
def runner_login():
    """Page that user sees when clicking Login in the Runner app"""
    from flask_login import current_user
    return render_template_string(
        RUNNER_LOGIN_PAGE, 
        logged_in=current_user.is_authenticated,
        success=False
    )

@runner_bp.route('/auth/runner-authorize')
def runner_authorize():
    """Generate token and send to local Runner app"""
    from flask_login import current_user, login_required
    
    if not current_user.is_authenticated:
        return redirect('/auth/runner-login')
    
    # Generate a long-lived token for the runner
    # In production, use proper JWT with expiration
    import secrets
    token = secrets.token_urlsafe(32)
    
    # Store token associated with user (add to your database)
    # For now, we'll use a simple approach - you should persist this
    # current_user.runner_token = token
    # db.session.commit()
    
    # The runner is listening on localhost:3742
    # We need to POST the token to it
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Connecting Runner...</title>
    <style>
        body {
            font-family: -apple-system, system-ui, sans-serif;
            background: #0f1419;
            color: #e7e9ea;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }
        .card {
            background: #1a1f26;
            border: 1px solid #2d3640;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
        }
        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid #2d3640;
            border-top-color: #3b82f6;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .success { color: #22c55e; font-size: 48px; }
        .error { color: #ef4444; }
    </style>
</head>
<body>
    <div class="card">
        <div class="spinner" id="spinner"></div>
        <p id="status">Connecting to Runner...</p>
    </div>
    <script>
        // Send token to local runner
        fetch('http://127.0.0.1:3742/auth-callback', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                token: '{{ token }}',
                email: '{{ email }}'
            })
        })
        .then(res => res.json())
        .then(data => {
            document.getElementById('spinner').className = 'success';
            document.getElementById('spinner').textContent = '✓';
            document.getElementById('status').textContent = 'Connected! You can close this window.';
        })
        .catch(err => {
            document.getElementById('spinner').style.display = 'none';
            document.getElementById('status').className = 'error';
            document.getElementById('status').textContent = 'Could not connect to Runner. Is it running?';
        });
    </script>
</body>
</html>
    ''', token=token, email=current_user.email)


# ================================================
# API ENDPOINT - Runner fetches user's flows
# ================================================

def runner_auth_required(f):
    """Decorator to verify runner token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing token'}), 401
        
        token = auth_header[7:]
        
        # Verify token - implement your own token verification
        # This should look up the token in your database
        # user = User.query.filter_by(runner_token=token).first()
        # if not user:
        #     return jsonify({'error': 'Invalid token'}), 401
        # request.user = user
        
        return f(*args, **kwargs)
    return decorated


@runner_bp.route('/api/runner/flows')
@runner_auth_required
def get_runner_flows():
    """Return user's flows for the runner"""
    # Get user from token (implement based on your auth)
    # user = request.user
    
    # Get user's flows from database
    # flows = Flow.query.filter_by(user_id=user.id).all()
    
    # For now, return empty - implement based on your data model
    flows = []
    
    return jsonify({
        'flows': [{
            'id': f.id,
            'name': f.name,
            'nodes': f.nodes,  # JSON field
            'connections': f.connections,  # JSON field
            'schedule': f.schedule,  # e.g., "every 5 minutes"
            'enabled': f.enabled
        } for f in flows]
    })


# ================================================
# REGISTER THE BLUEPRINT
# ================================================
# In your main app.py or __init__.py:
#
# from routes_runner import runner_bp
# app.register_blueprint(runner_bp)
#
