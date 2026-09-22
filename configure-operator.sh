#!/usr/bin/env bash
set -Eeuo pipefail

CFG_DIR="/etc/vici-users"
OPERATORS_FILE="${CFG_DIR}/operators.json"
PYTHON_BIN="/opt/vici-users/.venv/bin/python"

USERNAME="${1:-}"
ROLE="${2:-operator}"

if [ "$(id -u)" -ne 0 ]; then
  echo "[ERROR] Ejecuta como root" >&2
  exit 1
fi

if [ -z "$USERNAME" ]; then
  echo "Uso: $0 <username> [operator|admin]" >&2
  exit 1
fi

case "$ROLE" in
  operator|admin) ;;
  *)
    echo "[ERROR] Rol inválido: $ROLE" >&2
    exit 1
    ;;
esac

if [ ! -x "$PYTHON_BIN" ]; then
  echo "[ERROR] No existe $PYTHON_BIN" >&2
  exit 1
fi

mkdir -p "$CFG_DIR"
chmod 0750 "$CFG_DIR"

"$PYTHON_BIN" - "$OPERATORS_FILE" "$USERNAME" "$ROLE" <<'PY'
from __future__ import print_function

import getpass
import hashlib
import json
import os
import secrets
import sys
import tempfile

path, username, role = sys.argv[1:4]

password = getpass.getpass("Password nuevo para %s: " % username)
confirm = getpass.getpass("Repite el password: ")

if password != confirm:
    print("[ERROR] Los passwords no coinciden", file=sys.stderr)
    sys.exit(2)

if len(password) < 12:
    print("[ERROR] Usa al menos 12 caracteres", file=sys.stderr)
    sys.exit(3)

data = {}
if os.path.exists(path):
    try:
        with open(path, "r") as fh:
            current = json.load(fh)
        if isinstance(current, dict):
            data = current
    except Exception as exc:
        print("[ERROR] No se pudo leer %s: %s" % (path, exc), file=sys.stderr)
        sys.exit(4)

salt = secrets.token_bytes(16)
iterations = 260000
digest = hashlib.pbkdf2_hmac(
    "sha256",
    password.encode("utf-8"),
    salt,
    iterations,
)

data[username] = {
    "active": True,
    "role": role,
    "salt": salt.hex(),
    "iterations": iterations,
    "password_hash": digest.hex(),
}

directory = os.path.dirname(path) or "."
fd, tmp = tempfile.mkstemp(prefix=".operators.", dir=directory)

try:
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise

print("[OK] Operador actualizado: %s (%s)" % (username, role))
print("[OK] Archivo: %s" % path)
print("[OK] Password almacenado sólo como PBKDF2-SHA256")
PY

chown root:root "$OPERATORS_FILE"
chmod 0600 "$OPERATORS_FILE"

echo
echo "Reinicia la API:"
echo "  systemctl restart vici-users"
echo
echo "Valida:"
echo "  curl -s http://127.0.0.1:8094/api/health | $PYTHON_BIN -m json.tool"
