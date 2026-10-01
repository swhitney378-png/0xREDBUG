"""
Shared extension instances.

Instantiated here (not in __init__.py) so that models and routes can
import them without triggering circular-import issues.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."

limiter = Limiter(key_func=get_remote_address)
csrf = CSRFProtect()
