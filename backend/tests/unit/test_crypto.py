from core.crypto import decrypt_text, encrypt_text


def test_encrypt_decrypt_roundtrip():
    msg = "hello-tesht"
    ct = encrypt_text(msg)
    assert isinstance(ct, str)
    assert ct != msg
    pt = decrypt_text(ct)
    assert pt == msg
