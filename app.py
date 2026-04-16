"""
TINA / Semtech Data Intelligence Platform — Flask application entrypoint.

Run locally: python app.py
Then open http://127.0.0.1:5000/nexora/ for Nexora (GNOC assistant).
"""

import os

from flask import Flask, render_template

from alerts.routes import alerts_bp
from know_your_customers.routes import kyc_bp
from nexora.routes import nexora_bp
from pcap_analysis.routes import pcap_analysis_bp
from similarity_search.routes import similarity_bp
from status_page.routes import status_bp
from terminologies.routes import terms_bp


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-change-me")

    @app.route("/")
    def index():
        return render_template("index.html")

    app.register_blueprint(pcap_analysis_bp, url_prefix="/pcap_analysis")
    app.register_blueprint(similarity_bp, url_prefix="/similarity_search")
    app.register_blueprint(alerts_bp, url_prefix="/alerts")
    app.register_blueprint(kyc_bp, url_prefix="/kyc")
    app.register_blueprint(terms_bp, url_prefix="/terminologies")
    app.register_blueprint(status_bp, url_prefix="/status")
    app.register_blueprint(nexora_bp, url_prefix="/nexora")

    return app


app = create_app()


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("505.html"), 500


if __name__ == "__main__":
    # Local development — Nexora: http://127.0.0.1:5000/nexora/
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=True)
