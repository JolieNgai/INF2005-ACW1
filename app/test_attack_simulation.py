import json
from datetime import datetime, timedelta, timezone

from app.attack_simulation import (
    build_evidence_path,
    run_audio_attack_sweep,
    run_crypto_attack_sweep,
    run_image_attack_sweep,
    write_evidence,
)


def _by_id(results):
    return {result.test_id: result for result in results}


def test_crypto_attack_sweep_detects_supported_attacks():
    results = _by_id(run_crypto_attack_sweep())

    assert results["CRYPTO-POS-01"].actual_verification is True
    assert results["CRYPTO-POS-01"].passed is True

    for test_id in (
        "CRYPTO-NEG-01",
        "CRYPTO-NEG-02",
        "CRYPTO-NEG-03",
    ):
        assert results[test_id].actual_verification is False
        assert results[test_id].attack_detected is True
        assert results[test_id].passed is True


def test_image_attack_sweep_detects_supported_attacks():
    results = _by_id(run_image_attack_sweep())

    assert results["IMAGE-POS-01"].actual_verification is True
    assert results["IMAGE-POS-01"].passed is True

    for test_id in (
        "IMAGE-NEG-01",
        "IMAGE-NEG-02",
        "IMAGE-NEG-03",
        "IMAGE-NEG-04",
        "IMAGE-NEG-05",
        "IMAGE-NEG-06",
    ):
        assert results[test_id].actual_verification is False
        assert results[test_id].attack_detected is True
        assert results[test_id].passed is True


def test_audio_attack_sweep_detects_supported_attacks():
    results = _by_id(run_audio_attack_sweep())

    assert results["AUDIO-POS-01"].actual_verification is True
    assert results["AUDIO-POS-01"].passed is True

    for test_id in (
        "AUDIO-NEG-01",
        "AUDIO-NEG-02",
        "AUDIO-NEG-03",
        "AUDIO-NEG-04",
        "AUDIO-NEG-05",
        "AUDIO-NEG-06",
    ):
        assert results[test_id].actual_verification is False
        assert results[test_id].attack_detected is True
        assert results[test_id].passed is True


def test_write_evidence_creates_combined_json_report(tmp_path):
    results = (
        run_crypto_attack_sweep()
        + run_image_attack_sweep()
        + run_audio_attack_sweep()
    )
    sgt = timezone(timedelta(hours=8), name="SGT")
    generated_at = datetime(2026, 9, 23, 12, 30, 45, 123456, tzinfo=sgt)
    output_path = build_evidence_path(generated_at, tmp_path)

    written_path = write_evidence(results, output_path, generated_at)

    assert written_path == output_path
    assert output_path.name == "attack_results_20260923_123045_123456_SGT.json"

    report = json.loads(output_path.read_text(encoding="utf-8"))

    expected_test_ids = {
        "CRYPTO-POS-01",
        "CRYPTO-NEG-01",
        "CRYPTO-NEG-02",
        "CRYPTO-NEG-03",
        "IMAGE-POS-01",
        "IMAGE-NEG-01",
        "IMAGE-NEG-02",
        "IMAGE-NEG-03",
        "IMAGE-NEG-04",
        "IMAGE-NEG-05",
        "IMAGE-NEG-06",
        "AUDIO-POS-01",
        "AUDIO-NEG-01",
        "AUDIO-NEG-02",
        "AUDIO-NEG-03",
        "AUDIO-NEG-04",
        "AUDIO-NEG-05",
        "AUDIO-NEG-06",
    }
    actual_test_ids = {result["test_id"] for result in report["results"]}

    assert actual_test_ids == expected_test_ids
    assert report["generated_at_sgt"] == "2026-09-23T12:30:45.123456+08:00"
    assert report["component"] == "attack_simulation"
    assert report["components"] == [
        "audio_stego",
        "crypto_payload",
        "image_stego",
    ]

    expected_total = len(results)
    expected_passed = sum(result.passed for result in results)
    expected_failed = sum(not result.passed for result in results)
    expected_attacks_detected = sum(
        result.attack_detected is True for result in results
    )

    assert report["summary"]["total"] == expected_total
    assert report["summary"]["passed"] == expected_passed
    assert report["summary"]["failed"] == expected_failed
    assert report["summary"]["attacks_detected"] == expected_attacks_detected
    assert len(report["results"]) == expected_total


def test_attack_simulation_web_run_and_download(monkeypatch, tmp_path):
    """The web page should run the sweep and download the same JSON report."""

    monkeypatch.setenv("STEGO_SECRET_KEY", "attack-route-test-key")

    from app import attack_routes
    from app import create_app

    monkeypatch.setattr(attack_routes, "EVIDENCE_DIRECTORY", tmp_path)

    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    page_response = client.get("/attack-simulation")
    assert page_response.status_code == 200
    assert b"Run Attack Simulation" in page_response.data

    run_response = client.post("/attack-simulation/run")
    assert run_response.status_code == 200
    assert b"Total scenarios" in run_response.data
    assert b"CRYPTO-NEG-01" in run_response.data
    assert b"IMAGE-NEG-06" in run_response.data
    assert b"AUDIO-NEG-06" in run_response.data

    evidence_files = list(tmp_path.glob("attack_results_*_SGT.json"))
    assert len(evidence_files) == 1

    report = json.loads(evidence_files[0].read_text(encoding="utf-8"))
    assert report["summary"]["total"] == len(report["results"])

    download_response = client.get(
        f"/attack-simulation/evidence/{evidence_files[0].name}"
    )
    assert download_response.status_code == 200
    assert download_response.mimetype == "application/json"
    assert json.loads(download_response.data) == report

    csv_response = client.get(
        f"/attack-simulation/evidence/{evidence_files[0].name}/csv"
    )
    assert csv_response.status_code == 200
    assert csv_response.mimetype == "text/csv"
    csv_text = csv_response.data.decode("utf-8-sig")
    assert "Generated At (SGT)" in csv_text
    assert "CRYPTO-NEG-01" in csv_text
    assert "IMAGE-NEG-06" in csv_text
    assert "AUDIO-NEG-06" in csv_text
