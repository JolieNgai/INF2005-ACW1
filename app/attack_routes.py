"""Web interface for running and downloading attack-simulation evidence."""

import csv
from datetime import datetime
import io
import json
from pathlib import Path

from flask import Blueprint, abort, render_template, send_file, send_from_directory

from .attack_simulation import (
    SINGAPORE_TIMEZONE,
    build_evidence_path,
    run_audio_attack_sweep,
    run_crypto_attack_sweep,
    run_image_attack_sweep,
    write_evidence,
)


bp = Blueprint("attack", __name__, url_prefix="/attack-simulation")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIRECTORY = PROJECT_ROOT / "evidence"


@bp.get("")
def index():
    """Show the attack-simulation page without starting a test run."""

    return render_template("attack_simulation.html")


@bp.post("/run")
def run():
    """Run all supported attacks and show the newly generated evidence."""

    results = (
        run_crypto_attack_sweep()
        + run_image_attack_sweep()
        + run_audio_attack_sweep()
    )
    generated_at = datetime.now(SINGAPORE_TIMEZONE)
    output_path = build_evidence_path(generated_at, EVIDENCE_DIRECTORY)
    write_evidence(results, output_path, generated_at)

    report = json.loads(output_path.read_text(encoding="utf-8"))
    return render_template(
        "attack_simulation.html",
        generated_at=report["generated_at_sgt"],
        summary=report["summary"],
        results=report["results"],
        evidence_filename=output_path.name,
    )


@bp.get("/evidence/<path:filename>")
def download_evidence(filename: str):
    """Download one JSON report produced by the web simulation."""

    if (
        Path(filename).name != filename
        or not filename.startswith("attack_results_")
        or not filename.endswith("_SGT.json")
    ):
        abort(404)
    return send_from_directory(
        EVIDENCE_DIRECTORY,
        filename,
        as_attachment=True,
        mimetype="application/json",
    )


@bp.get("/evidence/<path:filename>/csv")
def download_evidence_csv(filename: str):
    """Convert one stored JSON report into an Excel-friendly CSV download."""

    if (
        Path(filename).name != filename
        or not filename.startswith("attack_results_")
        or not filename.endswith("_SGT.json")
    ):
        abort(404)

    evidence_path = EVIDENCE_DIRECTORY / filename
    if not evidence_path.is_file():
        abort(404)

    report = json.loads(evidence_path.read_text(encoding="utf-8"))
    summary = report["summary"]
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "Generated At (SGT)",
            "Total Scenarios",
            "Passed Expectations",
            "Failed Expectations",
            "Attacks Detected",
            "Test ID",
            "Component",
            "Scenario",
            "Expected",
            "Actual",
            "Result",
            "Attack Detected",
            "Evidence",
        ]
    )

    for result in report["results"]:
        component = result["test_id"].split("-", 1)[0].lower()
        writer.writerow(
            [
                report["generated_at_sgt"],
                summary["total"],
                summary["passed"],
                summary["failed"],
                summary["attacks_detected"],
                result["test_id"],
                component,
                result["attack"],
                "Verified" if result["expected_verification"] else "Rejected",
                "Verified" if result["actual_verification"] else "Rejected",
                "PASS" if result["passed"] else "SECURITY GAP",
                (
                    "N/A"
                    if result["attack_detected"] is None
                    else "Yes" if result["attack_detected"] else "No"
                ),
                result["evidence"],
            ]
        )

    csv_name = filename.removesuffix(".json") + ".csv"
    csv_bytes = output.getvalue().encode("utf-8-sig")
    return send_file(
        io.BytesIO(csv_bytes),
        mimetype="text/csv",
        as_attachment=True,
        download_name=csv_name,
    )
