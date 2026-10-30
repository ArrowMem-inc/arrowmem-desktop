"""Phone side of the pairing handshake for the ignored real-companion Rust tests.

Written from the protocol, NOT importing companion code: X25519 keypair, commitment
SHA256(nonce||pub), /pair-start, /pair-reveal (returns companion_nonce), HKDF-SHA256 with salt
phone_nonce+companion_nonce and info b"arrowbridge-pairing-code|"+companion_pub+phone_pub, first 4 bytes
big-endian, "%06d" % (n % 1000000).

usage: phone_side.py PORT MODE      MODE: start-reveal | start-only
       phone_side.py --selftest VECTORS_JSON
Prints one JSON line {"handshake_id":..,"code":..} (code null for start-only). Never prints a key.
"""
import base64, hashlib, http.client, json, secrets, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def derive_code(shared, phone_nonce, companion_nonce, companion_pub, phone_pub):
    material = HKDF(algorithm=hashes.SHA256(), length=32, salt=phone_nonce + companion_nonce,
                    info=b"arrowbridge-pairing-code|" + companion_pub + phone_pub).derive(shared)
    return "%06d" % (int.from_bytes(material[:4], "big") % 1000000)


def post(port, path, body):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", path, body=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    r = c.getresponse(); raw = r.read(); c.close()
    return r.status, (json.loads(raw) if raw else {})


def b64(x): return base64.b64encode(x).decode("ascii")


def run(port, mode):
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce = secrets.token_bytes(16)
    st, body = post(port, "/pair-start", {"public_key": b64(pub), "commitment": b64(hashlib.sha256(nonce + pub).digest())})
    if st != 200:
        return {"status": st, "handshake_id": None, "code": None}
    hid = body["handshake_id"]
    cpub = base64.b64decode(body["public_key"])
    if mode == "start-only":
        return {"status": st, "handshake_id": hid, "code": None}
    st, rb = post(port, "/pair-reveal", {"handshake_id": hid, "nonce": b64(nonce)})
    if st != 200:
        return {"status": st, "handshake_id": hid, "code": None}
    shared = priv.exchange(x25519.X25519PublicKey.from_public_bytes(cpub))
    code = derive_code(shared, nonce, base64.b64decode(rb["companion_nonce"]), cpub, pub)
    return {"status": 200, "handshake_id": hid, "code": code}


def selftest(path):
    cases = json.load(open(path))["cases"]
    for c in cases:
        got = derive_code(bytes.fromhex(c["shared_secret"]), bytes.fromhex(c["phone_nonce"]),
                          bytes.fromhex(c["companion_nonce"]), bytes.fromhex(c["companion_pub"]), bytes.fromhex(c["phone_pub"]))
        assert got == c["code"], (got, c["code"])
    print("vectors ok: %d" % len(cases))


if __name__ == "__main__":
    if sys.argv[1] == "--selftest":
        selftest(sys.argv[2])
    else:
        print(json.dumps(run(int(sys.argv[1]), sys.argv[2])))
