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

# Configuration du module JWT
app.config["JWT_SECRET_KEY"] = "Ma_clé_secrete"  # Ma clée privée
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1) # Durée du jeton
# Enable JWT tokens to be stored in cookies
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False  # Set to True in production (HTTPS)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # Set to True in production
jwt = JWTManager(app)


@jwt.additional_claims_loader
def add_claims_to_access_token(identity):
    if identity == "test":
        return {'role': 'admin'}
    return {'role': 'user'}


@app.route('/', methods=["GET"])
def home():
    response = make_response(render_template('accueil.html'))
    response.headers['Content-Type'] = 'text/html'
    return response


@app.route("/login", methods=["GET", "POST"], endpoint="login")
def login():
    if request.method == "GET":
        response = make_response(render_template('login.html'))
        response.headers['Content-Type'] = 'text/html'
        return response

    username = request.json.get("username", None)
    password = request.json.get("password", None)
    
    if username != "test" or password != "test":
        response = make_response(render_template('login.html', error="Nom d'utilisateur ou mot de passe incorrect"))
        response.headers['Content-Type'] = 'text/html'
        return response

    access_token = create_access_token(identity=username)

    # Retourner un jeton JWT dans la réponse
    response = make_response(redirect(url_for('protected')))
    set_access_cookies(response, access_token)
    return response


@app.route("/protected", methods=["GET"], endpoint="protected")
@jwt_required
def protected():
    current_user = get_jwt_identity()
    claims = get_jwt()
    response = make_response(render_template(
        'protected.html',
        username=current_user,
        role=claims.get('role')
    ))
    response.headers['Content-Type'] = 'text/html'
    return response


@app.route("/admin", methods=["GET"], endpoint="admin")
@jwt_required
def admin():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return render_template(
            'admin.html',
            error="Accès non autorisé"
        )
    return render_template(
        'admin.html',
        username=get_jwt_identity(),
        role=claims.get('role')
    )


@app.route("/logout")
def logout():
    response = make_response(redirect(url_for('login')))
    unset_jwt_cookies(response)
    return response


if __name__ == "__main__":
    app.run(debug=True)