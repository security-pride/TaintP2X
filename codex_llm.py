from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL | re.IGNORECASE)
    return fenced.group(1).strip() if fenced else text


def _extract_json_text(text: str) -> str:
    cleaned = _strip_code_fences(text)
    if cleaned.startswith(("{", "[")):
        return cleaned

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        return cleaned[start : end + 1].strip()
    return cleaned


def _run_codex(
    prompt: str,
    cwd: str | Path | None = None,
    model: str | None = None,
    timeout: int = 1800,
) -> tuple[int, str, str]:
    codex_bin = shutil.which("codex")
    if not codex_bin:
        raise FileNotFoundError("codex binary not found in PATH")

    workdir = Path(cwd) if cwd else Path.cwd()
    codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))

    with tempfile.TemporaryDirectory(prefix="codex_llm_") as tmpdir:
        last_message = Path(tmpdir) / "last_message.txt"
        command = [
            codex_bin,
            "exec",
            "--ephemeral",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--cd",
            str(workdir),
            "--output-last-message",
            str(last_message),
        ]
        if model:
            command.extend(["--model", model])
        command.append("-")

        environment = os.environ.copy()
        environment["CODEX_HOME"] = str(codex_home)
        process = subprocess.run(
            command,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
        message = ""
        if last_message.exists():
            message = last_message.read_text(encoding="utf-8", errors="ignore").strip()
        if not message:
            message = (process.stdout or process.stderr or "").strip()
        return process.returncode, message, (process.stderr or "").strip()


def codex_chat_json(
    prompt: str,
    *,
    cwd: str | Path | None = None,
    model: str | None = None,
    timeout: int = 1800,
) -> dict[str, Any]:
    """Run Codex and normalize its response to the existing OpenAI-style shape."""
    try:
        returncode, content, stderr = _run_codex(prompt, cwd=cwd, model=model, timeout=timeout)
        if not content:
            return {"error": "codex returned empty output", "returncode": returncode, "stderr": stderr}

        return {
            "choices": [{"message": {"content": _extract_json_text(content)}}],
            "returncode": returncode,
            "stderr": stderr,
            "raw_output": content,
        }
    except subprocess.TimeoutExpired as exc:
        return {"error": f"codex timeout: {exc}"}
    except Exception as exc:
        return {"error": f"codex error: {exc}"}
