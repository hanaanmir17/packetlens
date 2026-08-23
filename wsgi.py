"""
WSGI / dev-server entry point for PacketLens.

Run locally with:
    python wsgi.py
or:
    flask --app wsgi run
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
