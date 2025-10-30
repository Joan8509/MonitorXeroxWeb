import io, os, re, time, threading
from datetime import datetime
from flask import Blueprint, jsonify, request, Response, session, redirect, url_for, render_template
from functools import wraps

# Importa tus módulos internos
from .snmp_utils import fetch_supplies_generic, get_cached
from .auth import verify_user, find_user_id, update_username, update_password, login_required
from .export_xlsx import handle_export_xlsx_pivot, handle_export_xlsx_list_pivot

bp = Blueprint("routes", __name__)

# =========================== LOGIN / LOGOUT ===========================

def handle_login():
    """Maneja la autenticación."""
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        return render_template("login.html", error="Username and password required.")

    if not verify_user(username, password):
        return render_template("login.html", error="Invalid credentials.")

    session["user_id"] = find_user_id(username)
    session["username"] = username
    return redirect(url_for("routes.home"))

@bp.route("/login", methods=["GET", "POST"])
def login():
    return handle_login()

@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("routes.login"))

# =========================== HOME ===========================

@bp.route("/")
@login_required("home")
def home():
    username = session.get("username") or ""
    return render_template("home.html", username=username)

# =========================== ACCOUNT ===========================

def handle_account():
    """Maneja el formulario de cuenta."""
    user_id = session.get("user_id")
    username = session.get("username")

    if not user_id:
        return redirect(url_for("routes.login"))

    if request.method == "GET":
        return render_template("account.html", username=username)

    # POST
    new_username = request.form.get("username", "").strip()
    current_pw = request.form.get("current_password", "").strip()
    new_pw = request.form.get("new_password", "").strip()
    confirm_pw = request.form.get("confirm_password", "").strip()

    # Validar contraseña actual
    if not verify_user(username, current_pw):
        return render_template("account.html", username=username, error="Current password incorrect.")

    # Cambiar username
    if new_username and new_username != username:
        err = update_username(user_id, new_username)
        if err:
            return render_template("account.html", username=username, error=err)
        session["username"] = new_username
        username = new_username

    # Cambiar contraseña
    if new_pw:
        if new_pw != confirm_pw:
            return render_template("account.html", username=username, error="New passwords do not match.")
        if len(new_pw) < 6:
            return render_template("account.html", username=username, error="Password must be at least 6 characters.")
        update_password(user_id, new_pw)

    return render_template("account.html", username=username, success="Changes saved successfully.")

@bp.route("/account", methods=["GET", "POST"])
@login_required("account")
def account():
    return handle_account()

# =========================== API SUPPLIES ===========================

def handle_api_supplies():
    """Consulta una sola impresora."""
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    try:
        data = fetch_supplies_generic(ip)
        return jsonify(data)
    except Exception as e:
        print("[ERROR]", e)
        return jsonify({"error": f"SNMP error: {e}"}), 500

def handle_api_supplies_list():
    """Consulta varias impresoras separadas por coma."""
    ips = request.args.get("ips", "").replace("\n", ",").replace(";", ",").split(",")
    ips = [x.strip() for x in ips if x.strip()]
    if not ips:
        return jsonify({"error": "No IPs provided"}), 400

    results = []
    for ip in ips:
        try:
            data = fetch_supplies_generic(ip)
            results.append(data)
        except Exception as e:
            results.append({"ip": ip, "error": str(e)})

    return jsonify({"results": results})

@bp.route("/api/supplies")
@login_required("api_supplies")
def api_supplies():
    return handle_api_supplies()

@bp.route("/api/supplies_list")
@login_required("api_supplies_list")
def api_supplies_list():
    return handle_api_supplies_list()

# =========================== EXPORTS ===========================

@bp.route("/api/export_xlsx_pivot")
@login_required("export_xlsx_pivot")
def api_export_xlsx_pivot():
    ip = request.args.get("ip", "").strip()
    pct_max = request.args.get("pct_max")
    text = request.args.get("text", "")
    if not ip:
        return jsonify({"error": "Missing IP"}), 400
    data = fetch_supplies_generic(ip)
    return handle_export_xlsx_pivot(data, pct_max, text)

@bp.route("/api/export_xlsx_list_pivot")
@login_required("export_xlsx_list_pivot")
def api_export_xlsx_list_pivot():
    ips = request.args.get("ips", "").replace("\n", ",").replace(";", ",").split(",")
    ips = [x.strip() for x in ips if x.strip()]
    pct_max = request.args.get("pct_max")
    text = request.args.get("text", "")
    if not ips:
        return jsonify({"error": "No IPs provided"}), 400
    results = []
    for ip in ips:
        try:
            results.append(fetch_supplies_generic(ip))
        except Exception as e:
            results.append({"ip": ip, "error": str(e)})
    return handle_export_xlsx_list_pivot(results, pct_max, text)

# =========================== DEBUG / HEALTH ===========================

@bp.route("/api/debug")
@login_required("api_debug")
def api_debug():
    return jsonify({"session": dict(session)})

@bp.route("/healthz")
def healthz():
    return jsonify({"ok": True})
