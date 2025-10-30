from flask import Flask
import os
from .auth import init_auth_db, bootstrap_admin_from_env
from .routes import bp as routes_bp

def create_app():
    # base_dir = carpeta raíz del proyecto (donde está run.py)
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    template_path = os.path.join(base_dir, "templates")
    static_path = os.path.join(base_dir, "static")

    app = Flask(__name__, template_folder=template_path, static_folder=static_path)

    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "change-me-please"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(os.getenv("SESSION_COOKIE_SECURE", "0") == "1"),
    )

    # Inicializar DB y registrar rutas
    init_auth_db()
    bootstrap_admin_from_env()
    app.register_blueprint(routes_bp)

    return app
