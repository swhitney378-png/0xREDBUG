"""
Development entry point.

Load environment variables from .env first, then create and run the app.

For production use:
    gunicorn "wsgi:app" --workers 4 --bind 0.0.0.0:8000
    python maintenance_worker.py  # run exactly one maintenance worker
"""
from dotenv import load_dotenv
import os

load_dotenv()  # Must happen before app import so VAULTWARD_MASTER_SECRET is set

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    debug = os.environ.get("VAULTWARD_DEBUG", "0").strip().lower() in {"1", "true", "yes", "on"}
    app.run(debug=debug, host="0.0.0.0", port=3452)
