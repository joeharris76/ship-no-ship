from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ship_no_ship_service.config import Repository

SLUG = "example-owner/example-repo"
HEAD = "a" * 40


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    """A throwaway key made for this test run; no key is ever committed."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def key_file(tmp_path: Path, rsa_key: rsa.RSAPrivateKey) -> Path:
    path = tmp_path / "keys" / "app.pem"
    path.parent.mkdir()
    path.write_bytes(
        rsa_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    path.chmod(0o400)
    return path


@pytest.fixture
def repository(key_file: Path) -> Repository:
    return Repository(
        slug=SLUG, app_id=7, installation_id=9, key_path=key_file, bot_login="example-bot", base_branch="main"
    )
