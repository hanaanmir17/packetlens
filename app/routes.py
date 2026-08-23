"""
routes.py
---------
Flask routes / HTTP glue for PacketLens. All the real parsing and
detection logic lives in app.parser and app.anomaly (both Flask-free and
independently unit-testable) -- this module just wires HTTP requests to
those pure functions and serialises the results to JSON.
"""
import os
import tempfile
import uuid

from flask import Blueprint, current_app, jsonify, render_template, request

from app.anomaly import run_all_detections
from app.parser import parse_pcap, summarize

bp = Blueprint("main", __name__)


def _allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/api/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request. Field name must be 'file'."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    if not _allowed_file(file.filename):
        return jsonify({
            "error": "Unsupported file type. Please upload a .pcap, .pcapng, or .cap file."
        }), 400

    tmp_name = f"packetlens_{uuid.uuid4().hex}_{os.path.basename(file.filename)}"
    tmp_path = os.path.join(current_app.config["UPLOAD_FOLDER"], tmp_name)

    try:
        file.save(tmp_path)

        try:
            records = parse_pcap(tmp_path)
        except Exception as exc:  # malformed / unreadable capture
            return jsonify({"error": f"Could not parse capture file: {exc}"}), 400

        if not records:
            return jsonify({"error": "No packets could be read from this file."}), 400

        summary = summarize(records)
        detections = run_all_detections(records)

        return jsonify({
            "filename": file.filename,
            "summary": summary,
            "anomalies": detections,
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@bp.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})
