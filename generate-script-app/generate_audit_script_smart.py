"""Smart audit-script generator using the Claude Agent SDK.

"""
import asyncio
import json
import os
import re
import tempfile
from pathlib import Path

from claude_agent_sdk import query, ClaudeAgentOptions

from utils.script_builder import build_script, UnsafeCommand


def extract_pdf_text(pdf_path):
    """Return the full text of a PDF. Tries pypdf, falls back to pdfplumber.
    Raises RuntimeError if neither yields usable text."""
    text = ""
    try:
        from pypdf import PdfReader
        reader = PdfReader(pdf_path)
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception as e:
        print(f"pypdf extraction failed ({e}); trying pdfplumber...")

    if len(text.strip()) < 50:  # pypdf gave little/nothing - try pdfplumber
        try:
            import pdfplumber
            parts = []
            with pdfplumber.open(pdf_path) as pdf:
                for page in pdf.pages:
                    parts.append(page.extract_text() or "")
            text = "\n".join(parts)
        except Exception as e:
            print(f"pdfplumber extraction failed ({e}).")

    if len(text.strip()) < 50:
        raise RuntimeError(
            "Could not extract text from the PDF (it may be a scanned/image PDF "
            "needing OCR). The Smart path needs a text-based PDF."
        )
    return text



SYSTEM_PROMPT = """You are a security-benchmark analyst. You read a hardening benchmark document
and extract concrete, checkable configuration rules, emitting for each a single
READ-ONLY shell command that verifies the rule on a Linux host.

Hard rules:
- Every command MUST be read-only (grep, cat, stat, sysctl, systemctl is-enabled,
  getent, find without -delete/-exec, awk, sed -n, etc.). NEVER a command that
  writes, deletes, enables, disables, installs, or otherwise changes state.
- Prefer commands EXACTLY as written in the document when it provides them.
  Only derive a command when the document describes the check in prose.
- One single command per rule. No pipelines beyond a single pipe. No command
  chaining (; && || ` $() > <).
- If a section is not a concrete checkable rule (cover page, TOC, rationale,
  references), skip it.
You have exactly TWO tools: Read (to read the extracted benchmark text) and
Write (to create the one output file). You do NOT have Grep, Bash, or any other
tool - do not attempt to use them. The output file does not exist yet; create
it with a single Write call."""

PROMPT_TEMPLATE = """Use the Read tool to read the extracted benchmark text at '{text_path}'.
If it is long, read it in sections with Read's offset/limit - do NOT try Grep
or Bash, you don't have them.

Extract every concrete, checkable configuration rule. For each, produce an
object with:
  - "rule": a stable identifier (use the document's own rule number/ID when
    present, otherwise a short heading-derived id)
  - "command": ONE read-only shell command that checks the rule (lift it
    verbatim from the document when the document provides it)

Then make a SINGLE Write call to create '{out_path}' containing ONLY a JSON
array of these objects. The file does not exist yet, so just create it - do not
try to Read it first. No prose, no markdown fences - just the JSON array:
[
  {{"rule": "1.1.1", "command": "modprobe -n -v cramfs"}},
  {{"rule": "5.2.1", "command": "grep '^PermitRootLogin' /etc/ssh/sshd_config"}}
]

After the Write succeeds, reply with a one-line summary of how many rules you
extracted."""


def _extract_json_array(text):
    """Pull a JSON array out of the agent's output file, tolerating stray
    prose or code fences in case the model added them despite instructions."""
    text = text.strip()
    # strip markdown fences if present
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None


async def _run_agent(text_path, out_path, max_turns=20):
    """Drive the agent to read the extracted text and write the JSON file."""

    DENIED = [
        "Bash", "PowerShell", "Edit", "NotebookEdit", "Task", "TaskOutput",
        "TaskStop", "WebFetch", "WebSearch", "Glob", "Grep", "Skill",
        "ToolSearch", "CronCreate", "CronDelete", "CronList", "ScheduleWakeup",
        "EnterPlanMode", "ExitPlanMode", "EnterWorktree", "ExitWorktree",
        "AskUserQuestion", "TodoWrite", "Monitor", "RemoteTrigger",
        "PushNotification",
    ]
    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        # Auto-approve the two tools the agent legitimately needs...
        allowed_tools=["Read", "Write"],
        disallowed_tools=DENIED,
        max_turns=max_turns,
        cwd=".",
        env={
            "CLAUDE_STREAM_IDLE_TIMEOUT_MS": "900000",   # 15 min of stream idle
            "API_TIMEOUT_MS": "900000",                   # 15 min per request
            "CLAUDE_CODE_MAX_RETRIES": "3",
        },
        model=os.getenv("SMART_MODEL", "claude-haiku-4-5"),
    )
    prompt = PROMPT_TEMPLATE.format(text_path=text_path, out_path=out_path)

    final_text = []
    async for message in query(prompt=prompt, options=options):
        # Surface progress; the SDK yields structured messages.
        print(message)
        text = getattr(message, "text", None)
        if text:
            final_text.append(text)
    return "\n".join(final_text)


def _upload_to_minio(local_path, object_name):
    """Same MinIO upload contract as the Standard path."""
    from minio import Minio

    endpoint = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    bucket = os.getenv("MINIO_BUCKET", "audit-scripts")
    client = Minio(
        endpoint,
        access_key=os.getenv("MINIO_ACCESS_KEY", ""),
        secret_key=os.getenv("MINIO_SECRET_KEY", ""),
        secure=os.getenv("MINIO_SECURE", "false").lower() in ("1", "true", "yes"),
    )
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)
    client.fput_object(bucket, object_name, local_path, content_type="application/x-sh")
    return f"{bucket}/{object_name}"


def generate_script_smart(benchmark_name, pdf_path):
    """Smart path entrypoint. Extracts PDF text, has the agent read that text
    and propose rules, validates every proposed command through script_builder,
    assembles the script, uploads to MinIO, and cleans up all temp files.

    Returns the MinIO location string, or None if nothing usable was produced.
    """
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"benchmark PDF not found: {pdf_path}")

    text = extract_pdf_text(pdf_path)
    print(f"Extracted {len(text)} chars of text from {os.path.basename(pdf_path)}")

    tmp_txt_fd, tmp_txt = tempfile.mkstemp(suffix=".txt", prefix=f"{benchmark_name}_text_")
    with os.fdopen(tmp_txt_fd, "w", encoding="utf-8") as f:
        f.write(text)

    tmp_json = os.path.join(
        tempfile.gettempdir(),
        f"{benchmark_name}_rules_{os.urandom(6).hex()}.json",
    )
    tmp_script = None
    try:
        # 1. Agent reads the extracted TEXT and writes the rules JSON.
        asyncio.run(_run_agent(tmp_txt, tmp_json))

        raw = Path(tmp_json).read_text(encoding="utf-8") if os.path.exists(tmp_json) else ""
        rules = _extract_json_array(raw)
        if not rules:
            print("Smart generation produced no parseable rules.")
            return None

        # 2. Normalise into (rule, command) pairs.
        checks = []
        for item in rules:
            if isinstance(item, dict) and item.get("rule") and item.get("command"):
                checks.append((str(item["rule"]), str(item["command"])))
        if not checks:
            print("No valid rule/command pairs in agent output.")
            return None

        # 3. SAME safety gate as the Standard path: validate + build.
        script_text, accepted, rejected = build_script(benchmark_name, checks)
        print(f"\nSmart path: {len(accepted)} checks accepted, {len(rejected)} rejected.")
        for rule, command, reason in rejected:
            print(f"  REJECTED rule {rule}: {reason}  ({command!r})")
        if not accepted:
            print("All proposed commands failed validation - nothing to upload.")
            return None

        # 4. Write final script to temp, upload, clean up.
        tmp_fd, tmp_script = tempfile.mkstemp(suffix=".sh", prefix=f"{benchmark_name}_")
        with os.fdopen(tmp_fd, "w") as f:
            f.write(script_text)
        location = _upload_to_minio(tmp_script, f"{benchmark_name}.sh")
        print(f"Uploaded to MinIO: {location}")
        return location

    finally:
        for p in (tmp_txt, tmp_json, tmp_script):
            if p and os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass


