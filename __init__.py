from flask import (
    Flask, render_template, jsonify, request, 
    make_response, redirect, url_for
)
from datetime import timedelta
from flask_jwt_extended import (
    create_access_token, get_jwt_identity, jwt_required,
    JWTManager, get_jwt, set_access_cookies, unset_jwt_cookies
)

app = Flask(__name__)

# JWT Configuration
app.config["JWT_SECRET_KEY"] = "Ma_clé_secrete"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False  # True in production (HTTPS)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # Enable in production
jwt = JWTManager(app)

@jwt.additional_claims_loader
def add_claims_to_access_token(identity):
    return {'role': 'admin'} if identity == "test" else {'role': 'user'}

@app.route('/', methods=["GET"])
def home():
    return render_template('accueil.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template('login.html')

    # Extract username and password based on content type
    if request.is_json:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
    else:
        username = request.form.get("username")
        password = request.form.get("password")

    # Validate credentials
    if username != "test" or password != "test":
        # Return error based on client's Accept header
        if request.accept_mimetypes.accept_html:
            return render_template('login.html', error="Invalid credentials"), 401
        else:
            return jsonify({"msg": "Bad username or password"}), 401

    # Create JWT token
    access_token = create_access_token(identity=username)

    # Respond based on client type
    if request.accept_mimetypes.accept_html:
        response = make_response(redirect(url_for('protected')))
        set_access_cookies(response, access_token)
        return response
    else:
        return jsonify(access_token=access_token), 200

@app.route("/protected", methods=["GET"])
@jwt_required
def protected():
    current_user = get_jwt_identity()
    claims = get_jwt()
    return render_template('protected.html', username=current_user, role=claims.get('role'))

@app.route("/admin", methods=["GET"])
@jwt_required
def admin():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return render_template('admin.html', error="Unauthorized access"), 403
    return render_template('admin.html', username=get_jwt_identity(), role=claims.get('role'))

@app.route("/logout")
def logout():
    response = make_response(redirect(url_for('login')))
    unset_jwt_cookies(response)
    return response

if __name__ == "__main__":
    app.run(debug=True)
