from flask import Flask
import os
from .auth import init_auth_db, bootstrap_admin_from_env
from .routes import bp as routes_bp

def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "change-me-please"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(os.getenv("SESSION_COOKIE_SECURE", "0") == "1"),
    )

    # Inicializar base de datos de usuarios
    init_auth_db()
    bootstrap_admin_from_env()

    # Registrar blueprint principal
    app.register_blueprint(routes_bp)

    return app

