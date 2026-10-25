"""ThreatLens AI — Backend server runner."""
import os
from pathlib import Path
from dotenv import load_dotenv

# Root configuration is authoritative; backend/.env is a local fallback.
# Environment variables supplied by the process still take precedence.
ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / '.env')
load_dotenv(Path(__file__).resolve().parent / '.env')

from app import create_app
app = create_app()

if __name__ == '__main__':
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('API_PORT', '5000'))
    debug = os.getenv('FLASK_DEBUG', 'true').lower() in ('true', '1', 'yes')
    print(f"Starting ThreatLens AI Flask server on http://{host}:{port} (debug={debug})")
    app.run(host=host, port=port, debug=debug)
