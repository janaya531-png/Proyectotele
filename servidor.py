import os
import firebase_admin
from firebase_admin import credentials, auth
from flask import Flask, request, jsonify
from flask_cors import CORS
import json

# ── Firebase Admin ────────────────────────────────────────
try:
    raw = os.environ.get('FIREBASE_KEY')
    if raw:
        cred_dict = json.loads(raw)
        cred = credentials.Certificate(cred_dict)
        print("✅ FIREBASE_KEY encontrada en variables de entorno")
    else:
        print("⚠️ FIREBASE_KEY no encontrada, intentando archivo local...")
        cred = credentials.Certificate('serviceAccountKey.json')
        print("✅ serviceAccountKey.json cargado")
except Exception as e:
    print(f"❌ Error inicializando Firebase: {e}")
    cred = None

if cred:
    try:
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://telerobotica-593cb-default-rtdb.firebaseio.com'
        })
        print("✅ Firebase inicializado correctamente")
    except Exception as e:
        print(f"❌ Error en initialize_app: {e}")

# ── Constantes ────────────────────────────────────────────
OWNER_EMAIL = 'janaya531@unab.edu.co'  # ← Solo el owner tiene permisos totales

# ── Flask ─────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def health():
    return jsonify({
        'ok': True,
        'status': 'Biobrazo API online 🤖',
        'firebase': 'configured' if cred else 'not-configured'
    })

@app.route('/usuarios', methods=['GET'])
def listar_usuarios():
    if not cred:
        return jsonify({'ok': False, 'error': 'Firebase no configurado'}), 500
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
    if not cred:
        return jsonify({'ok': False, 'error': 'Firebase no configurado'}), 500
    
    data = request.json
    email_admin = data.get('email_admin')  # Email de quién está creando
    
    # ✅ PROTECCIÓN: Solo owner puede crear admins
    if data.get('rol') == 'admin' and email_admin != OWNER_EMAIL:
        return jsonify({
            'ok': False,
            'error': '❌ Solo el owner puede crear admins'
        }), 403
    
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
    if not cred:
        return jsonify({'ok': False, 'error': 'Firebase no configurado'}), 500
    
    data = request.json
    email_admin = data.get('email_admin')  # Email de quién está actualizando
    
    try:
        # Obtener el usuario actual
        usuario = auth.get_user(uid)
        rol_actual = (usuario.custom_claims or {}).get('rol', 'operador')
        
        # ✅ PROTECCIÓN: Si intenta cambiar rol, solo el owner puede
        if 'rol' in data and data['rol'] != rol_actual:
            if email_admin != OWNER_EMAIL:
                return jsonify({
                    'ok': False,
                    'error': '❌ Solo el owner puede cambiar roles'
                }), 403
        
        # Actualizar nombre
        auth.update_user(uid, display_name=data.get('nombre', ''))
        
        # Cambiar rol si se especifica
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
    if not cred:
        return jsonify({'ok': False, 'error': 'Firebase no configurado'}), 500
    
    data = request.json or {}
    email_admin = data.get('email_admin')  # Email de quién intenta eliminar
    
    # ✅ PROTECCIÓN 1: Solo owner puede eliminar
    if email_admin != OWNER_EMAIL:
        return jsonify({
            'ok': False,
            'error': '❌ Solo el owner puede eliminar usuarios'
        }), 403
    
    try:
        # ✅ PROTECCIÓN 2: Owner no puede eliminarse a sí mismo
        usuario = auth.get_user(uid)
        if usuario.email == OWNER_EMAIL:
            return jsonify({
                'ok': False,
                'error': '❌ No puedes eliminarte a ti mismo'
            }), 403
        
        auth.delete_user(uid)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400

# ─────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
