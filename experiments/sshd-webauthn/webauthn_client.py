#!/usr/bin/env python3
"""Client SSH de test (paramiko) qui s'authentifie avec une signature WebAuthn.
Usage : webauthn_client.py <dossier> <rp_id> <hôte> <port> <utilisateur> [commande]"""
import sys, logging
import paramiko
sys.path.insert(0, sys.argv[1])
import fake_passkey_agent as fp

d, rp_id, host, port, user = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
cmd = sys.argv[6] if len(sys.argv) > 6 else "true"
k = fp.load_or_create(d)

class PasskeyKey(paramiko.PKey):
    public_blob = None
    def get_name(self): return fp.SIGTYPE.decode()
    def asbytes(self): return fp.pub_blob(k, rp_id)
    def can_sign(self): return True
    def sign_ssh_data(self, data, algorithm=None):
        return fp.webauthn_sign(k, rp_id, data, 1)

logging.basicConfig(level=logging.WARNING)
t = paramiko.Transport((host, port))
t.start_client(timeout=15)
print("serveur :", t.remote_version)
try:
    t.auth_publickey(user, PasskeyKey())
    ch = t.open_session(); ch.exec_command(cmd)
    print("AUTHENTIFIÉ — sortie :", ch.makefile().read().decode().strip())
except Exception as e:
    print("ÉCHEC :", type(e).__name__, e)
t.close()
