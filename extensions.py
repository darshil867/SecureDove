"""
Flask extensions initialization
This module holds extension objects to avoid circular imports
"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

# Initialize extensions without binding to app
# They will be bound to the app in app.py using init_app()
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    strategy="fixed-window"
)

csrf = CSRFProtect()
