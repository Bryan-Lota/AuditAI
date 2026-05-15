import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any


class SlitherExecutionError(RuntimeError):
    pass


def _line_from_source_mapping(source_mapping: dict[str, Any]) -> int | None:
    lines = source_mapping.get("lines") or []
    if lines:
        return int(lines[0])
    line = source_mapping.get("line")
    return int(line) if line else None


def _function_name(element: dict[str, Any]) -> str | None:
    name = element.get("name")
    element_type = str(element.get("type") or "").lower()
    if name and "function" in element_type:
        return str(name)
    return None


def _normalize_detector(detector: dict[str, Any]) -> dict[str, Any]:
    elements = detector.get("elements") or []
    first_mapping = next((element.get("source_mapping") for element in elements if element.get("source_mapping")), {})
    first_function = next((_function_name(element) for element in elements if _function_name(element)), None)
    return {
        "vulnerability_type": detector.get("check") or detector.get("title") or "unknown",
        "severity": detector.get("impact") or "Informational",
        "function_name": first_function,
        "line_number": _line_from_source_mapping(first_mapping),
        "detector": detector.get("check"),
        "source_mapping": json.dumps(first_mapping),
        "slither_description": detector.get("description") or detector.get("markdown") or "No Slither description provided.",
    }


async def run_slither(source_code: str, contract_name: str) -> list[dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="auditai-") as temp_dir:
        contract_path = Path(temp_dir) / contract_name
        contract_path.write_text(source_code, encoding="utf-8")

        process = await asyncio.create_subprocess_exec(
            "slither",
            str(contract_path),
            "--json",
            "-",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

    if process.returncode not in (0, 255):
        detail = (stderr or stdout).decode(errors="replace").strip()
        raise SlitherExecutionError(f"Slither failed: {detail}")

    try:
        payload = json.loads(stdout.decode(errors="replace") or "{}")
    except json.JSONDecodeError as exc:
        raise SlitherExecutionError("Slither did not emit valid JSON.") from exc

    detectors = payload.get("results", {}).get("detectors", [])
    return [_normalize_detector(detector) for detector in detectors]
