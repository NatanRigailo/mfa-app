from flask import Flask, render_template, jsonify, request, flash, redirect, session, url_for
import urllib.parse
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, select, func
import pyotp
import os
import hmac
import secrets
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

APP_NAME = os.getenv("APP_NAME", "MFA Tokens")
TABLE_NAME = os.getenv("TABLE_NAME", "mfa_tokens")
EDIT_PASS = os.getenv("EDIT_PASS", "")
REGISTER_ABLE = os.getenv("REGISTER_ABLE", "true").lower() == "true"
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "5"))
DEMO_MODE     = os.getenv("DEMO_MODE", "false").lower() == "true"

DEMO_TOKENS = [
    "AWS – Produção",
    "AWS – Staging",
    "GitHub",
    "Google Workspace",
    "Cloudflare",
    "Datadog",
    "Grafana",
    "Terraform Cloud",
    "Slack",
    "Linear",
    "Vercel",
    "PagerDuty",
]

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
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
db = SQLAlchemy(app)


class MfaToken(db.Model):
    __tablename__ = TABLE_NAME
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    secret = db.Column(db.String(80), unique=True, nullable=False)
    ativo = db.Column(db.Boolean, default=True, nullable=False)


def get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf() -> bool:
    token = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not token or not expected:
        return False
    return hmac.compare_digest(token, expected)


@app.context_processor
def inject_globals():
    return {"app_name": APP_NAME, "csrf_token": get_csrf_token}


@app.before_request
def log_request():
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"{request.method} {request.path}")


@app.route("/", methods=["GET", "POST"])
def index():
    edit_mode = session.get("edit_mode", False)

    if request.method == "POST":
        if not edit_mode:
            flash("Modo de edição não está ativo.", "error")
            return redirect(url_for("index"))
        if not validate_csrf():
            flash("Token de segurança inválido. Recarregue a página e tente novamente.", "error")
            return redirect(url_for("index"))

        tokens = db.session.execute(select(MfaToken)).scalars().all()
        for token in tokens:
            new_name = request.form.get(f"name_{token.id}", "").strip()
            if not new_name:
                continue
            new_ativo = request.form.get(f"ativo_{token.id}") == "on"
            duplicate = db.session.execute(
                select(MfaToken).where(MfaToken.name == new_name, MfaToken.id != token.id)
            ).scalar()
            if duplicate:
                flash(f"Nome '{new_name}' já está em uso.", "error")
                return redirect(url_for("index"))
            token.name = new_name
            token.ativo = new_ativo

        try:
            db.session.commit()
            flash("Alterações salvas!", "success")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error saving token edits: {e}")
            flash("Erro ao salvar alterações.", "error")
        return redirect(url_for("index"))

    tokens_query = db.session.execute(
        select(MfaToken).order_by(MfaToken.name)
    ).scalars().all()
    if not edit_mode:
        tokens_query = [t for t in tokens_query if t.ativo]

    grouped_tokens = {k: list(g) for k, g in groupby(tokens_query, key=lambda x: x.name[0].upper())}
    tokens_keys = [t.name for t in tokens_query]

    return render_template("index.html", grouped_tokens=grouped_tokens, tokens_keys=tokens_keys, edit_mode=edit_mode)


@app.route("/get_new_codes")
def get_new_codes():
    tokens = db.session.execute(select(MfaToken).where(MfaToken.ativo.is_(True))).scalars().all()
    codes = {}
    for token in tokens:
        try:
            codes[token.name] = pyotp.TOTP(token.secret).now()
        except Exception as e:
            logger.error(f"Error generating code for '{token.name}': {e}")
    return jsonify(codes=codes)


@app.route("/toggle_edit", methods=["POST"])
def toggle_edit():
    if not validate_csrf():
        flash("Token de segurança inválido.", "error")
        return redirect(url_for("index"))
    # Sair sempre funciona, independente de senha
    if session.get("edit_mode"):
        session.pop("edit_mode", None)
        flash("Modo de edição desativado.", "info")
        return redirect(url_for("index"))
    palavra = request.form.get("palavra", "").strip()
    if not EDIT_PASS or hmac.compare_digest(palavra, EDIT_PASS):
        session["edit_mode"] = True
        flash("Modo de edição ativado!", "success")
    else:
        flash("Senha incorreta.", "error")
    return redirect(url_for("index"))


@app.route("/delete/<int:token_id>", methods=["POST"])
def delete_token(token_id):
    if not session.get("edit_mode"):
        flash("Acesso negado.", "error")
        return redirect(url_for("index"))
    if not validate_csrf():
        flash("Token de segurança inválido.", "error")
        return redirect(url_for("index"))
    token = db.session.get(MfaToken, token_id)
    if token:
        try:
            name = token.name
            db.session.delete(token)
            db.session.commit()
            flash(f"Token '{name}' removido.", "success")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting token {token_id}: {e}")
            flash("Erro ao remover token.", "error")
    return redirect(url_for("index"))


def sanitize_secret(secret: str) -> str | None:
    cleaned = secret.replace(" ", "").upper()
    try:
        pyotp.TOTP(cleaned).now()
        return cleaned
    except Exception:
        return None


def extract_secret_from_uri(uri: str) -> str | None:
    if not uri.startswith("otpauth://totp/"):
        return None
    parsed = urllib.parse.urlparse(uri)
    params = urllib.parse.parse_qs(parsed.query)
    return params.get("secret", [None])[0]


@app.route("/register", methods=["GET", "POST"])
def register():
    if not REGISTER_ABLE:
        return render_template("register_disabled.html")

    if request.method == "POST":
        if not validate_csrf():
            flash("Token de segurança inválido.", "error")
            return redirect(url_for("register"))

        name = request.form.get("name", "").strip()
        secret_form = request.form.get("secret", "").strip()
        secret = None

        if secret_form:
            secret = sanitize_secret(secret_form)
            if secret is None:
                flash("Secret inválido. Verifique a chave Base32.", "error")
                return redirect(url_for("register"))

        if "qr_code" in request.files:
            qr_file = request.files["qr_code"]
            if qr_file.filename:
                try:
                    decoded_qr = decode(Image.open(qr_file))
                    if not decoded_qr:
                        flash("Não foi possível decodificar o QR Code.", "error")
                        return redirect(url_for("register"))
                    uri = decoded_qr[0].data.decode("utf-8")
                    raw = extract_secret_from_uri(uri)
                    if not raw:
                        flash("QR Code não contém um URI otpauth://totp/ válido.", "error")
                        return redirect(url_for("register"))
                    secret = sanitize_secret(raw)
                    if secret is None:
                        flash("Secret extraído do QR Code é inválido.", "error")
                        return redirect(url_for("register"))
                except Exception as e:
                    flash(f"Erro ao processar o QR Code: {e}", "error")
                    return redirect(url_for("register"))

        if not name or not secret:
            flash("Nome e secret são obrigatórios.", "error")
            return redirect(url_for("register"))

        existing = db.session.execute(select(MfaToken).where(MfaToken.name == name)).scalar()
        if existing:
            flash(f"Já existe um token com o nome '{name}'.", "error")
            return redirect(url_for("register"))

        try:
            db.session.add(MfaToken(name=name, secret=secret))
            db.session.commit()
            flash("Token registrado com sucesso!", "success")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error registering token '{name}': {e}")
            flash("Erro ao salvar o token.", "error")
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/healthz")
def health_check():
    try:
        db.session.execute(text("SELECT 1"))
        return "OK"
    except Exception as e:
        return str(e), 500


def seed_demo():
    count = db.session.execute(select(func.count()).select_from(MfaToken)).scalar()
    if count == 0:
        for name in DEMO_TOKENS:
            db.session.add(MfaToken(name=name, secret=pyotp.random_base32(), ativo=True))
        db.session.commit()
        logger.info(f"Demo: seeded {len(DEMO_TOKENS)} tokens")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if DEMO_MODE:
            seed_demo()
    from waitress import serve
    port = int(os.getenv("PORT", 5000))
    serve(app, host="0.0.0.0", port=port)  # nosec B104
