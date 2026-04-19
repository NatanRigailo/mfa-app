from flask import Flask, render_template, jsonify, request, flash, redirect, session, url_for
import urllib.parse
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import pyotp
import os
from pyzbar.pyzbar import decode
from PIL import Image
from itertools import groupby
import logging

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# Config
app_name = os.getenv("APP_NAME", "MFA Tokens")
table_name = os.getenv("TABLE_NAME", "mfa_tokens")
edit_pass = os.getenv("EDIT_PASS", "")
register_able = os.getenv("REGISTER_ABLE", "true").lower() == "true"

# Database: MySQL se DB_HOST estiver definido, senão SQLite
db_host = os.getenv("DB_HOST")
if db_host:
    db_user = os.getenv("DB_USER")
    db_password = urllib.parse.quote_plus(os.getenv("DB_PASSWORD", ""))
    db_name = os.getenv("DB_DATABASE")
    db_url = f"mysql+mysqlconnector://{db_user}:{db_password}@{db_host}/{db_name}"
    logger.info(f"Using MySQL: {db_host}/{db_name}")
else:
    db_url = "sqlite:////data/tokens.db"
    logger.info("Using SQLite: /data/tokens.db")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.urandom(24).hex()
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class MfaToken(db.Model):
    __tablename__ = table_name
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    secret = db.Column(db.String(80), unique=True, nullable=False)
    ativo = db.Column(db.Boolean, default=True, nullable=False)


@app.context_processor
def inject_globals():
    return {"app_name": app_name}


@app.before_request
def log_request():
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"{request.method} {request.path}")
        for header, value in request.headers.items():
            logger.debug(f"  {header}: {value}")


@app.route("/", methods=["GET", "POST"])
def index():
    edit_mode = session.get("edit_mode", False)

    if request.method == "POST" and edit_mode:
        for token in MfaToken.query.all():
            new_name = request.form.get(f"name_{token.id}")
            ativo_value = request.form.get(f"ativo_{token.id}") == "on"
            if new_name and (token.name != new_name or token.ativo != ativo_value):
                token.name = new_name
                token.ativo = ativo_value
        db.session.commit()
        flash("Alterações salvas!", "success")
        return redirect(url_for("index"))

    tokens_query = MfaToken.query.order_by(MfaToken.name).all()
    if not edit_mode:
        tokens_query = [t for t in tokens_query if t.ativo]

    grouped_tokens = {k: list(g) for k, g in groupby(tokens_query, key=lambda x: x.name[0].upper())}
    tokens_keys = [token.name for token in tokens_query]

    return render_template("index.html", grouped_tokens=grouped_tokens, tokens_keys=tokens_keys, edit_mode=edit_mode)


@app.route("/get_new_codes")
def get_new_codes():
    active_tokens = MfaToken.query.filter_by(ativo=True).all()
    codes = {}
    for token in active_tokens:
        try:
            codes[token.name] = pyotp.TOTP(token.secret).now()
        except Exception as e:
            logger.error(f"Error generating code for '{token.name}': {e}")
            codes[token.name] = "Erro"
    return jsonify(codes=codes)


@app.route("/toggle_edit", methods=["POST"])
def toggle_edit():
    palavra = request.form.get("palavra", "").strip()
    if palavra == edit_pass:
        session["edit_mode"] = True
        flash("Modo de edição ativado!", "success")
    else:
        session.pop("edit_mode", None)
        flash("Modo de edição desativado.", "info")
    return redirect(url_for("index"))


def sanitize_secret(secret: str) -> str:
    return secret.replace(" ", "").upper()


def extract_secret_from_uri(uri: str) -> str | None:
    parsed = urllib.parse.urlparse(uri)
    params = urllib.parse.parse_qs(parsed.query)
    return params.get("secret", [None])[0]


@app.route("/register", methods=["GET", "POST"])
def register():
    if not register_able:
        return render_template("register_disabled.html")

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        secret_form = request.form.get("secret", "").strip()
        secret = sanitize_secret(secret_form) if secret_form else None

        if "qr_code" in request.files:
            qr_file = request.files["qr_code"]
            if qr_file.filename:
                try:
                    decoded_qr = decode(Image.open(qr_file))
                    if decoded_qr:
                        uri = decoded_qr[0].data.decode("utf-8")
                        secret = extract_secret_from_uri(uri)
                    else:
                        flash("Não foi possível decodificar o QR Code.", "error")
                        return redirect(url_for("register"))
                except Exception as e:
                    flash(f"Erro ao processar o QR Code: {e}", "error")
                    return redirect(url_for("register"))

        if not name or not secret:
            flash("Nome e secret são obrigatórios.", "error")
            return redirect(url_for("register"))

        db.session.add(MfaToken(name=name, secret=secret))
        db.session.commit()
        flash("Token registrado com sucesso!", "success")
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/healthz")
def health_check():
    try:
        db.session.execute(text("SELECT 1"))
        return "OK"
    except Exception as e:
        return str(e), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    from waitress import serve
    serve(app, host="0.0.0.0", port=5000)
