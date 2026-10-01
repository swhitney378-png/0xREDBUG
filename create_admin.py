import os
os.environ["SECRET_KEY"] = "dev-secret"
os.environ["VAULTWARD_MASTER_SECRET"] = "0123456789abcdef0123456789abcdef"

from app import create_app
from app.extensions import db
from app.models.user import User, Role

app = create_app()
with app.app_context():
    user = User.query.filter(
        (User.username == "admin") | (User.email == "admin@vaultward.local")
    ).first()
    if not user:
        user = User(username="admin", email="admin@vaultward.local", role=Role.ADMIN, tier="enterprise", is_active=True)
    user.username = "admin"
    user.email = "admin@vaultward.local"
    user.role = Role.ADMIN
    user.tier = "enterprise"
    user.is_active = True
    user.set_password("AdminPass123!")
    db.session.add(user)
    db.session.commit()
    print(f"ADMIN_USER_READY {user.id} {user.username} {user.role} {user.tier}")
