import os
import firebase_admin
from firebase_admin import credentials, auth
from flask import Flask, request, jsonify
from flask_cors import CORS
import json

# ── Firebase Admin ────────────────────────────────────────
# En Railway se usa variable de entorno FIREBASE_KEY (JSON como string)
raw = os.environ.get('FIREBASE_KEY')
if raw:
    cred_dict = json.loads(raw)
    cred = credentials.Certificate(cred_dict)
else:
    # Fallback local: usa el archivo
    cred = credentials.Certificate('serviceAccountKey.json')

firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://telerobotica-593cb-default-rtdb.firebaseio.com'
})

# ── Flask ─────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def health():
    return jsonify({'ok': True, 'status': 'Biobrazo API online 🤖'})

@app.route('/usuarios', methods=['GET'])
def listar_usuarios():
    try:
        usuarios = []
        page = auth.list_users()
        while page:
            for u in page.users:
                usuarios.append({
                    'uid':    u.uid,
                    'email':  u.email or '',
                    'nombre': u.display_name or '',
                    'rol':    (u.custom_claims or {}).get('rol', 'operador'),
                })
            page = page.get_next_page()
        return jsonify({'ok': True, 'usuarios': usuarios})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/usuarios', methods=['POST'])
def crear_usuario():
    data = request.json
    try:
        u = auth.create_user(
            email=data['email'],
            password=data['password'],
            display_name=data.get('nombre', ''),
        )
        rol = data.get('rol', 'operador')
        claims = {'rol': rol}
        if rol == 'admin':
            claims['admin'] = True
        auth.set_custom_user_claims(u.uid, claims)
        return jsonify({'ok': True, 'uid': u.uid})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400

@app.route('/usuarios/<uid>', methods=['PUT'])
def actualizar_usuario(uid):
    data = request.json
    try:
        auth.update_user(uid, display_name=data.get('nombre', ''))
        if 'rol' in data:
            rol = data['rol']
            claims = {'rol': rol}
            if rol == 'admin':
                claims['admin'] = True
            auth.set_custom_user_claims(uid, claims)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400

@app.route('/usuarios/<uid>', methods=['DELETE'])
def eliminar_usuario(uid):
    try:
        auth.delete_user(uid)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400

# ─────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
