from flask import Blueprint, render_template, redirect, url_for, request

web_bp = Blueprint("web", __name__)


@web_bp.route("/")
def index():
    return redirect(url_for("web.login"))


@web_bp.route("/login")
def login():
    return render_template("login.html")


@web_bp.route("/register")
def register():
    return render_template("register.html")


@web_bp.route("/vault")
def vault():
    return render_template("vault.html")