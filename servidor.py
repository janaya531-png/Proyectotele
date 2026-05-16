import os
import json
import firebase_admin
from firebase_admin import credentials, auth
from flask import Flask, request, jsonify
from flask_cors import CORS

# ───────────────────────────────────────────────
# CONFIG
# ───────────────────────────────────────────────
OWNER_UID = "wbSTxZClwMX8aipBdxoKKfrkBiV2"

# ───────────────────────────────────────────────
# FIREBASE INIT
# ───────────────────────────────────────────────
cred = None

try:
    raw = os.environ.get("FIREBASE_KEY")
    if raw:
        cred_dict = json.loads(raw)
        cred = credentials.Certificate(cred_dict)
        print("✅ FIREBASE_KEY cargada desde variables de entorno")
    else:
        cred = credentials.Certificate("serviceAccountKey.json")
        print("✅ serviceAccountKey.json cargado")
except Exception as e:
    print("❌ Error cargando credenciales Firebase:", e)
    cred = None

if cred:
    try:
        firebase_admin.initialize_app(cred)
        print("✅ Firebase inicializado correctamente")
    except Exception as e:
        print("❌ Error inicializando Firebase:", e)

# ───────────────────────────────────────────────
# FLASK
# ───────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ───────────────────────────────────────────────
# HELPERS
# ───────────────────────────────────────────────
def get_token_data():
    """Verifica el token enviado por el frontend y devuelve datos del usuario."""
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return None, ("Falta token Authorization Bearer", 401)

    token = auth_header.replace("Bearer ", "").strip()

    try:
        decoded = auth.verify_id_token(token)
        return decoded, None
    except Exception as e:
        return None, (f"Token inválido: {str(e)}", 401)


def is_owner(decoded):
    return decoded.get("uid") == OWNER_UID


def get_role(decoded):
    return decoded.get("rol", "operador")


def is_admin(decoded):
    return get_role(decoded) == "admin"


def require_admin(decoded):
    if not (is_admin(decoded) or is_owner(decoded)):
        return False
    return True


# ───────────────────────────────────────────────
# ROUTES
# ───────────────────────────────────────────────
@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "status": "Biobrazo API online 🤖",
        "firebase": "configured" if cred else "not-configured"
    })


# ───────────────────────────────────────────────
# LISTAR USUARIOS (ADMIN/OWNER)
# ───────────────────────────────────────────────
@app.route("/usuarios", methods=["GET"])
def listar_usuarios():
    if not cred:
        return jsonify({"ok": False, "error": "Firebase no configurado"}), 500

    decoded, err = get_token_data()
    if err:
        return jsonify({"ok": False, "error": err[0]}), err[1]

    if not require_admin(decoded):
        return jsonify({"ok": False, "error": "No autorizado"}), 403

    try:
        usuarios = []
        page = auth.list_users()

        while page:
            for u in page.users:
                usuarios.append({
                    "uid": u.uid,
                    "email": u.email or "",
                    "nombre": u.display_name or "",
                    "rol": (u.custom_claims or {}).get("rol", "operador"),
                })
            page = page.get_next_page()

        return jsonify({"ok": True, "usuarios": usuarios})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ───────────────────────────────────────────────
# CREAR USUARIO (ADMIN/OWNER)
# ───────────────────────────────────────────────
@app.route("/usuarios", methods=["POST"])
def crear_usuario():
    if not cred:
        return jsonify({"ok": False, "error": "Firebase no configurado"}), 500

    decoded, err = get_token_data()
    if err:
        return jsonify({"ok": False, "error": err[0]}), err[1]

    if not require_admin(decoded):
        return jsonify({"ok": False, "error": "No autorizado"}), 403

    data = request.json or {}

    email = data.get("email")
    password = data.get("password")
    nombre = data.get("nombre", "")
    rol = data.get("rol", "operador")

    if not email:
        return jsonify({"ok": False, "error": "Falta email"}), 400
    if not password:
        return jsonify({"ok": False, "error": "Falta password"}), 400

    if rol not in ["admin", "operador", "viewer"]:
        rol = "operador"

    try:
        u = auth.create_user(
            email=email,
            password=password,
            display_name=nombre
        )

        claims = {"rol": rol}
        if rol == "admin":
            claims["admin"] = True

        auth.set_custom_user_claims(u.uid, claims)

        return jsonify({"ok": True, "uid": u.uid})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ───────────────────────────────────────────────
# EDITAR USUARIO (ADMIN/OWNER)
# ───────────────────────────────────────────────
@app.route("/usuarios/<uid>", methods=["PUT"])
def actualizar_usuario(uid):
    if not cred:
        return jsonify({"ok": False, "error": "Firebase no configurado"}), 500

    decoded, err = get_token_data()
    if err:
        return jsonify({"ok": False, "error": err[0]}), err[1]

    if not require_admin(decoded):
        return jsonify({"ok": False, "error": "No autorizado"}), 403

    data = request.json or {}

    try:
        usuario = auth.get_user(uid)
        rol_actual = (usuario.custom_claims or {}).get("rol", "operador")

        # actualizar nombre
        if "nombre" in data:
            auth.update_user(uid, display_name=data.get("nombre", ""))

        # cambiar rol
        if "rol" in data:
            rol_nuevo = data["rol"]

            if rol_nuevo not in ["admin", "operador", "viewer"]:
                rol_nuevo = "operador"

            # 🔒 si el usuario es admin, solo owner puede modificarlo
            if rol_actual == "admin" and not is_owner(decoded):
                return jsonify({"ok": False, "error": "Solo el owner puede modificar un admin"}), 403

            claims = {"rol": rol_nuevo}
            if rol_nuevo == "admin":
                claims["admin"] = True

            auth.set_custom_user_claims(uid, claims)

        return jsonify({"ok": True})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ───────────────────────────────────────────────
# ELIMINAR USUARIO (ADMIN/OWNER)
# ───────────────────────────────────────────────
@app.route("/usuarios/<uid>", methods=["DELETE"])
def eliminar_usuario(uid):
    if not cred:
        return jsonify({"ok": False, "error": "Firebase no configurado"}), 500

    decoded, err = get_token_data()
    if err:
        return jsonify({"ok": False, "error": err[0]}), err[1]

    if not require_admin(decoded):
        return jsonify({"ok": False, "error": "No autorizado"}), 403

    try:
        usuario = auth.get_user(uid)
        rol_usuario = (usuario.custom_claims or {}).get("rol", "operador")

        # 🔒 owner no se puede eliminar
        if usuario.uid == OWNER_UID:
            return jsonify({"ok": False, "error": "No puedes eliminar al owner"}), 403

        # 🔒 admin no puede eliminar admins
        if rol_usuario == "admin" and not is_owner(decoded):
            return jsonify({"ok": False, "error": "Solo el owner puede eliminar admins"}), 403

        auth.delete_user(uid)
        return jsonify({"ok": True})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ───────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
