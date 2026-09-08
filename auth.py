"""
auth.py
Session-based authentication and role-based authorization helpers.

Design note: authorization is enforced here, on the server, for every
protected route. The interface hides controls a user's role does not
permit, but that is a usability convenience only -- the real access-
control boundary is these decorators, consistent with the "server
enforces, client merely reflects" principle from the system design.
"""

from functools import wraps
from flask import session, redirect, url_for, flash, abort


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))
            if session.get("role") not in allowed_roles:
                # Authorization failure -- deliberately generic, and logged
                # by the caller's audit trail via the route itself.
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator
