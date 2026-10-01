from dotenv import load_dotenv
import os

load_dotenv()

from app import create_app

app = create_app()

if __name__ == "__main__":
    debug = os.environ.get("VAULTWARD_DEBUG", "0").strip().lower() in {"1", "true", "yes", "on"}
    app.run(debug=debug, host="0.0.0.0", port=3452)
