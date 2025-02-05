from flask import Flask
from flask import render_template
from flask import jsonify
from flask import make_response
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import get_jwt_claims
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

from datetime import timedelta


app = Flask(__name__)                                                                                                                  

# Configuration du module JWT
app.config["JWT_SECRET_KEY"] = "Ma_clé_secrete"  # Ma clée privée
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1) # Durée du jeton
jwt = JWTManager(app)

@jwt.user_claims_loader
def add_claims_to_access_token(identity):
    if identity == "admin":
        return {'role': 'admin'}
    return {'role': 'user'}

@app.route('/')
def hello_world():
    response = make_response(render_template('accueil.html'))
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    
    if not username or not password:
        return jsonify({"msg": "Champs manquants"}), 400
        
    if username != "test" or password != "test":
        return jsonify({"msg": "Mauvais utilisateur ou mot de passe"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route("/protected", methods=["GET"])
@jwt_required
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route("/admin", methods=["GET"])
@jwt_required()
def admin():
    claims = get_jwt_claims()
    if claims['role'] != 'admin':
        return jsonify({
            "status": "error",
            "msg": "Vous n'avez pas les droits pour accéder à cette page"
        }), 403
    return jsonify({
        "status": "success",
        "msg": "Accès autorisé"
    }), 200

if __name__ == "__main__":
    app.run(debug=True)