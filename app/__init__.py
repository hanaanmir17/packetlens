"""
PacketLens Flask application factory.
"""
from __future__ import annotations

import os
import tempfile
from typing import Optional

from flask import Flask


def create_app(config: Optional[dict] = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=200 * 1024 * 1024,  # 200 MB upload cap
        UPLOAD_FOLDER=tempfile.gettempdir(),
        ALLOWED_EXTENSIONS={"pcap", "pcapng", "cap"},
    )
    if config:
        app.config.update(config)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)

    return app
