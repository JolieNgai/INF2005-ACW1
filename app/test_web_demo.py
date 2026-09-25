import pytest
from flask import Flask
from PIL import Image
from app.image_stego import embed_payload, extract_payload
from app.start_location import WrongStartLocationError


def test_web_upload_demo_and_disable(tmp_path, capsys):
    app = Flask(__name__)
    key = "secret-not-to-be-logged"
    cover, stego = tmp_path / "cover.png", tmp_path / "stego.png"
    Image.new("RGB", (64, 64)).save(cover)
    with app.test_request_context("/embed", method="POST"):
        embed_payload(cover, stego, b"payload", key, 3)
    with app.test_request_context("/verify", method="POST"):
        assert extract_payload(stego, key, 3) == b"payload"
    output = capsys.readouterr().out
    assert "[START LOCATION]" in output
    assert "ENCODER" in output and "DECODER" in output
    assert "Wrong Start Location: HMAC rejected" in output
    assert key not in output
    with app.test_request_context("/verify", method="POST"):
        with pytest.raises(WrongStartLocationError):
            extract_payload(stego, key, 1)
    assert "UPLOAD RECOVERY FAILED" in capsys.readouterr().out
    app.config["START_LOCATION_DEMO"] = False
    with app.test_request_context("/verify", method="POST"):
        assert extract_payload(stego, key, 3) == b"payload"
    assert capsys.readouterr().out == ""
