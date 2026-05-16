import os
import json
import firebase_admin
from firebase_admin import credentials, auth
from flask import Flask, request, jsonify
from flask_cors import CORS

# ───────────────────────────────────────────────
# CONFIG
# ───────────────────────────────────────────────
OWNER_EMAIL = "janaya531@unab.edu.co"

# ───────────────────────────────────────────────
# FIREBASE INIT
# ───────────────────────────────────────────────
cred = None

try:
    raw = os.environ.get("FIREBASE_KEY")
    if raw:
        cred_dict = json.loads(raw)
        cred = credentials.Certificate(cred_dict)
        print("✅ FIREBASE_KEY encontrada en variables de entorno")
    else:
        print("⚠️ FIREBASE_KEY no encontrada, intentando archivo local...")
        cred = credentials.Certificate("serviceAccountKey.json")
        print("✅ serviceAccountKey.json cargado")
except Exception as e:
    print(f"❌ Error inicializando Firebase credentials: {e}")
    cred = None

if cred:
    try:
        firebase_admin.initialize_app(cred, {
            "databaseURL": "https://telerobotica-593cb-default-rtdb.firebaseio.com"
        })
        print("✅ Firebase inicializado correctamente")
    except Exception as e:
        print(f"❌ Error en initialize_app: {e}")

# ───────────────────────────────────────────────
# FLASK INIT
# ───────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ───────────────────────────────────────────────
# HELPERS
# ───────────────────────────────────────────────
def get_user_role_by_email(email: str):
    """Devuelve el rol de un usuario dado su email."""
    if not email:
        return None

    try:
        u = auth.get_user_by_email(email)
        claims = u.custom_claims or {}
        return claims.get("rol", "operador")
    except Exception:
        return None


def is_owner(email: str):
    return email == OWNER_EMAIL


def is_admin_or_owner(email: str):
    rol = get_user_role_by_email(email)
    return rol == "admin" or is_owner(email)


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
# LISTAR USUARIOS
# ───────────────────────────────────────────────
@app.route("/usuarios", methods=["GET"])
def listar_usuarios():
    if not cred:
        return jsonify({"ok": False, "error": "Firebase no configurado"}), 500

    try:
        usuarios = []
        page = auth.list_users()

        while page:
            for u in page.users:
                usuarios.append({
                    "uid": u.uid,
                    "email": u.email or "",
                    "nombre": u.display_name or "",
                    "rol": (u.custom_claims or {}).get("rol", "operador")
                })
            page = page.get_next_page()

        return jsonify({"ok": True, "usuarios": usuarios})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ───────────────────────────────────────────────
# CREAR USUARIO
# ───────────────────────────────────────────────
@app.route("/usuarios", methods=["POST"])
def crear_usuario():
    if not cred:
        return jsonify({"ok": False, "error": "Firebase no configurado"}), 500

    data = request.json or {}

    email_admin = data.get("email_admin")
    email = data.get("email")
    password = data.get("password")
    nombre = data.get("nombre", "")
    rol = data.get("rol", "operador")

    if not email_admin:
        return jsonify({"ok": False, "error": "Falta email_admin"}), 400

    if not is_admin_or_owner(email_admin):
        return jsonify({"ok": False, "error": "❌ No autorizado"}), 403

    # 🔒 Solo owner puede crear admins
    if rol == "admin" and not is_owner(email_admin):
        return jsonify({
            "ok": False,
            "error": "❌ Solo el owner puede crear admins"
        }), 403

    if not email or not password:
        return jsonify({"ok": False, "error": "Email y password son obligatorios"}), 400

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
# ACTUALIZAR USUARIO
# ───────────────────────────────────────────────
@app.route("/usuarios/<uid>", methods=["PUT"])
def actualizar_usuario(uid):
    if not cred:
        return jsonify({"ok": False, "error": "Firebase no configurado"}), 500

    data = request.json or {}
    email_admin = data.get("email_admin")

    if not email_admin:
        return jsonify({"ok": False, "error": "Falta email_admin"}), 400

    if not is_admin_or_owner(email_admin):
        return jsonify({"ok": False, "error": "❌ No autorizado"}), 403

    try:
        usuario = auth.get_user(uid)
        claims_actuales = usuario.custom_claims or {}
        rol_actual = claims_actuales.get("rol", "operador")

        # 🔒 Admins NO pueden editar otros admins
        if rol_actual == "admin" and not is_owner(email_admin):
            return jsonify({
                "ok": False,
                "error": "❌ No puedes editar a otro admin"
            }), 403

        # actualizar nombre si viene
        if "nombre" in data:
            auth.update_user(uid, display_name=data.get("nombre", ""))

        # actualizar rol si viene
        if "rol" in data:
            rol_nuevo = data["rol"]

            if rol_nuevo not in ["admin", "operador", "viewer"]:
                rol_nuevo = "operador"

            # 🔒 Solo owner puede crear/cambiar a admin
            if rol_nuevo == "admin" and not is_owner(email_admin):
                return jsonify({
                    "ok": False,
                    "error": "❌ Solo el owner puede cambiar a rol admin"
                }), 403

            # Aplicar nuevo rol
            new_claims = {"rol": rol_nuevo}
            if rol_nuevo == "admin":
                new_claims["admin"] = True

            auth.set_custom_user_claims(uid, new_claims)

        return jsonify({"ok": True})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ───────────────────────────────────────────────
# ELIMINAR USUARIO
# ───────────────────────────────────────────────
@app.route("/usuarios/<uid>", methods=["DELETE"])
def eliminar_usuario(uid):
    if not cred:
        return jsonify({"ok": False, "error": "Firebase no configurado"}), 500

    data = request.json or {}
    email_admin = data.get("email_admin")

    if not email_admin:
        return jsonify({"ok": False, "error": "Falta email_admin"}), 400

    if not is_admin_or_owner(email_admin):
        return jsonify({"ok": False, "error": "❌ No autorizado"}), 403

    try:
        usuario = auth.get_user(uid)
        rol_usuario = (usuario.custom_claims or {}).get("rol", "operador")

        # 🔒 Owner no puede eliminarse a sí mismo
        if usuario.email == OWNER_EMAIL:
            return jsonify({
                "ok": False,
                "error": "❌ No puedes eliminarte a ti mismo"
            }), 403

        # 🔒 Si es admin, solo owner puede eliminarlo
        if rol_usuario == "admin" and not is_owner(email_admin):
            return jsonify({
                "ok": False,
                "error": "❌ Solo el owner puede eliminar admins"
            }), 403

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
