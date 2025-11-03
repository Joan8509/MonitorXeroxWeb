# -*- coding: utf-8 -*-
import os
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from .auth import verify_user, find_user_id, update_username, update_password, login_required
from .snmp_utils import fetch_supplies_generic
from .export_xlsx import handle_export_xlsx_list_pivot, handle_export_xlsx_pivot
from concurrent.futures import ThreadPoolExecutor, as_completed

bp = Blueprint("routes", __name__)

# ------------------------- LOGIN -------------------------
@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if verify_user(username, password):
            session["user_id"] = find_user_id(username)
            session["username"] = username
            return redirect(url_for("routes.home"))
        return render_template("login.html", error="Invalid username or password")
    return render_template("login.html")

# ------------------------- LOGOUT -------------------------
@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("routes.login"))

# ------------------------- ACCOUNT -------------------------
@bp.route("/account", methods=["GET", "POST"])
@login_required()
def account():
    message = None
    if request.method == "POST":
        user_id = session.get("user_id")
        new_username = request.form.get("new_username")
        new_password = request.form.get("new_password")
        if new_username:
            msg = update_username(user_id, new_username)
            if msg:
                message = msg
            else:
                session["username"] = new_username
                message = "Username updated successfully."
        if new_password:
            update_password(user_id, new_password)
            message = "Password updated successfully."
    return render_template("account.html", message=message, username=session.get("username"))

# ------------------------- HOME -------------------------
@bp.route("/")
@login_required()
def home():
    return render_template("home.html", username=session.get("username"))

# ------------------------- API: SUPPLIES -------------------------
@bp.route("/api/supplies", methods=["GET"])
@login_required()
def api_supplies():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "Missing IP"}), 400
    data = fetch_supplies_generic(ip)
    return jsonify(data)

# ------------------------- API: SUPPLIES LIST -------------------------
@bp.route("/api/supplies_list", methods=["POST"])
@login_required()
def api_supplies_list():
    ips_raw = request.form.get("ips", "").replace(",", "\n").splitlines()
    ips = [ip.strip() for ip in ips_raw if ip.strip()]
    if not ips:
        return jsonify({"results": []})

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_supplies_generic, ip): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                data = future.result()
                results.append(data)
            except Exception:
                results.append({
                    "ip": ip,
                    "printer_name": "Error",
                    "model": "N/A",
                    "black_impressions": -1,
                    "items": []
                })
    return jsonify({"results": results})

# ------------------------- EXPORT XLSX -------------------------
@bp.route("/api/export_xlsx_pivot", methods=["POST"])
@login_required()
def api_export_xlsx_pivot():
    data = request.get_json()
    return handle_export_xlsx_pivot(data)

@bp.route("/api/export_xlsx_list_pivot", methods=["POST"])
@login_required()
def api_export_xlsx_list_pivot():
    data = request.get_json()
    return handle_export_xlsx_list_pivot(data)

# ------------------------- HEALTH -------------------------
@bp.route("/healthz")
def healthz():
    return "OK", 200
