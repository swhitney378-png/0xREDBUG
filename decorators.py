from functools import wraps
from flask import abort, jsonify, request
from flask_login import current_user
from ..models.user import Role


def require_role(*roles):
    """Restrict endpoint to one or more roles. Usage: @require_role(Role.DOCTOR, Role.ADMIN)"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator


def require_tier(*tiers):
    """Restrict endpoint to users on specific subscription tiers."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.tier not in tiers:
                return jsonify({
                    "error": "upgrade_required",
                    "message": f"This feature requires a {' or '.join(tiers)} subscription.",
                    "current_tier": current_user.tier,
                }), 402
            return f(*args, **kwargs)
        return wrapped
    return decorator


def admin_only(f):
    """Shorthand for require_role(Role.ADMIN)."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != Role.ADMIN:
            abort(403)
        return f(*args, **kwargs)
    return wrapped
