"""TLS interception support: local CA + per-host leaf certificates.

Generates a self-signed OWSI root CA on first run (persisted to the project
directory) and signs per-host leaf certs on demand, exactly like a real MITM
proxy. The user installs ca-cert.pem in the browser/OS trust store once.
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import threading
from typing import Dict, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertificateAuthority:
    def __init__(self, cert_dir: str):
        self.cert_dir = cert_dir
        os.makedirs(cert_dir, exist_ok=True)
        self.ca_key_path = os.path.join(cert_dir, "ca-key.pem")
        self.ca_cert_path = os.path.join(cert_dir, "ca-cert.pem")
        self._lock = threading.Lock()
        self._cache: Dict[str, Tuple[bytes, bytes]] = {}
        self._load_or_create_ca()

    # ------------------------------------------------------------------
    def _load_or_create_ca(self) -> None:
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), None)
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
            return
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "OWSI Local Interception CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OMEGA Web Security Interceptor"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .add_extension(x509.KeyUsage(
                    digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False), True)
                .sign(key, hashes.SHA256()))
        with open(self.ca_key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        os.chmod(self.ca_key_path, 0o600)
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        self.ca_key, self.ca_cert = key, cert

    # ------------------------------------------------------------------
    def leaf_for_host(self, host: str) -> Tuple[bytes, bytes]:
        """Return (cert_pem, key_pem) for *host*, cached."""
        with self._lock:
            if host in self._cache:
                return self._cache[host]
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
            now = datetime.datetime.now(datetime.timezone.utc)
            b = (x509.CertificateBuilder()
                 .subject_name(name).issuer_name(self.ca_cert.subject)
                 .public_key(key.public_key())
                 .serial_number(x509.random_serial_number())
                 .not_valid_before(now - datetime.timedelta(days=1))
                 .not_valid_after(now + datetime.timedelta(days=820))
                 .add_extension(x509.BasicConstraints(ca=False, path_length=None), True))
            try:
                ip = ipaddress.ip_address(host)
                san = x509.SubjectAlternativeName([x509.IPAddress(ip)])
            except ValueError:
                san = x509.SubjectAlternativeName([x509.DNSName(host)])
            b = b.add_extension(san, critical=False)
            cert = b.sign(self.ca_key, hashes.SHA256())
            pair = (cert.public_bytes(serialization.Encoding.PEM),
                    key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
            self._cache[host] = pair
            return pair

    @property
    def fingerprint_sha256(self) -> str:
        return self.ca_cert.fingerprint(hashes.SHA256()).hex(":")
