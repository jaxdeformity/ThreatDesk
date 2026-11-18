"""Claude Code subprocess runner, the real agent execution engine.

Spawns a ``claude --dangerously-skip-permissions`` subprocess per agent
turn, parses its ``--output-format stream-json --verbose`` output line
by line, and yields typed events. Each event describes one observable
thing Claude did: started a session, thought, called a tool, got a
tool result, emitted text, finished.

The triage orchestrator iterates the event stream, appends each event
to the triage's ``events.jsonl``, rebroadcasts it to the UI via SSE,
and treats ``session_complete`` as the end of the run.

## Usage

```python
runner = ClaudeRunner()
async for event in runner.run_turn(
    system_prompt_append="Read .claude/agents/threat-triage.md and follow it.",
    user_prompt="Triage request TRG-…; input brief at triages/TRG-…/input.json.",
    cwd=REPO_ROOT,
):
    print(event)
```

## Security notes

- The subprocess runs as the user who launched ThreatDesk. If that
  user is root, Claude refuses ``--dangerously-skip-permissions`` and we
  surface the error. Don't ``sudo`` this tool.
- ``--add-dir`` is scoped to the triage directory + the repo root.
- Stdout is consumed in a non-blocking loop so a malicious/malformed
  output stream can't hang the server indefinitely; we also enforce a
  configurable per-turn timeout.

## Event shape

Every yielded dict has ``kind`` as the discriminator plus ``ts``:

- ``kind: "session_started"``, ``session_id``, ``model``, ``cwd``
- ``kind: "thinking"``, ``text`` (extended thinking block)
- ``kind: "text"``, ``text`` (assistant message text)
- ``kind: "tool_call"``, ``tool_id``, ``tool_name``, ``input_preview``,
  ``input`` (full dict for callers that need it)
- ``kind: "tool_result"``, ``tool_id``, ``result_preview``, ``is_error``
- ``kind: "session_complete"``, ``cost_usd``, ``duration_ms``,
  ``num_turns``, ``result``
- ``kind: "error"``, ``message`` (subprocess-level error, not tool error)
- ``kind: "raw"``, fallback for unrecognized event types; includes the
  original event payload for debug
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from threatdesk import debug_logger



def agent_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Environment additions for every claude agent process.

    Default: agents inherit ANTHROPIC_API_KEY (or Bedrock/Vertex env) from
    the server process, so an enterprise bills to its own key. With the
    runtime setting ``use_subscription`` on, the key is blanked and the
    agent runs on the logged-in Claude subscription instead.
    Per-agent overrides are applied last.
    """
    from threatdesk import runtime_settings

    env = {"CLAUDE_CODE_ENTRYPOINT": "threatdesk"}
    if runtime_settings.load().get("use_subscription"):
        env["ANTHROPIC_API_KEY"] = ""
    env.update(overrides or {})
    return env


def _windows_claude_exe_candidates() -> list[Path]:
    """Standard Windows install paths for the real ``claude.exe``.

    Rooted in the user-local npm prefix since that's where `npm install
    -g @anthropic-ai/claude-code` puts its tree. The outer ``bin/``
    ``claude.exe`` is the small launcher; the nested
    ``claude-code-win32-x64/claude.exe`` is the full ~250MB native
    binary. Either works, we prefer the outer one as canonical.
    """
    roots: list[Path] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(Path(appdata) / "npm")
    roots.append(Path.home() / ".npm-global")
    roots.append(Path("C:/Program Files/nodejs"))

    candidates: list[Path] = []
    for root in roots:
        candidates.extend([
            root / "node_modules" / "@anthropic-ai" / "claude-code" / "bin" / "claude.exe",
            root / "node_modules" / "@anthropic-ai" / "claude-code" / "node_modules"
                 / "@anthropic-ai" / "claude-code-win32-x64" / "claude.exe",
        ])
    return candidates


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class RunnerConfig:
    """Per-runner configuration.

    Most of these are overridable per-call, but carry sensible defaults
    so the orchestrator code stays clean.
    """
    model: str = "claude-fable-5-2"
    claude_binary: str | None = None          # None = look up on PATH
    timeout_s: float = 900.0                   # 15 min per turn
    max_output_bytes: int = 64 * 1024 * 1024   # 64 MB stdout cap
    # asyncio.StreamReader default per-line limit is 64KB, easily blown
    # by a single stream-json tool_result containing a file read or a
    # large Bash output. Bump to 10 MB so a fat tool_result doesn't kill
    # the entire turn with "Separator is found, but chunk is longer than limit".
    stdout_line_limit: int = 10 * 1024 * 1024  # 10 MB per line
    extra_args: list[str] = field(default_factory=list)


class ClaudeRunner:
    """Async wrapper around the ``claude`` CLI.

    Instances are cheap, create one per triage run.
    The runner keeps no state between calls beyond the resolved binary
    path and config. Sessions are continued via the ``session_id``
    parameter to ``run_turn``.
    """

    def __init__(self, config: RunnerConfig | None = None) -> None:
        self.config = config or RunnerConfig()
        self._binary = self._resolve_binary()

    # ── Binary resolution ────────────────────────────────────────────
    def _resolve_binary(self) -> str | None:
        """Find the claude binary to invoke.

        On Windows we deliberately prefer ``claude.exe`` over
        ``claude.CMD``. The .CMD wrapper routes through cmd.exe, which:
          (a) imposes an 8191-char argv limit, and
          (b) stdout pipe buffering quirks through the cmd→node→pty path
              can hold up all output until the child exits. We saw both
              in production: pid spawned but zero events streamed until
              the subprocess died.
        The real ``claude.exe`` is a native binary and avoids both
        issues. It lives under
        ``%APPDATA%\\npm\\node_modules\\@anthropic-ai\\claude-code\\bin\\``.
        """
        if self.config.claude_binary:
            return self.config.claude_binary

        # First: try preferred locations on Windows
        if sys.platform == "win32":
            for candidate in _windows_claude_exe_candidates():
                if candidate.exists():
                    return str(candidate)

        # Fallback: whatever PATH resolves
        return shutil.which("claude")

    def available(self) -> bool:
        """Cheap precheck, is the CLI installed and on PATH?"""
        return self._binary is not None

    def version(self) -> str | None:
        """Best-effort version detection; None on failure."""
        if not self._binary:
            return None
        try:
            import subprocess
            out = subprocess.run(
                [self._binary, "--version"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            line = (out.stdout or out.stderr or "").strip().splitlines()
            return line[0] if line else None
        except (OSError, subprocess.TimeoutExpired):
            return None

    # ── Primary API ──────────────────────────────────────────────────
    async def run_turn(
        self,
        *,
        user_prompt: str,
        system_prompt_append: str | None = None,
        cwd: Path | str,
        session_id: str | None = None,
        allowed_tools: list[str] | None = None,
        add_dirs: list[Path | str] | None = None,
        dangerous: bool = True,
        model: str | None = None,
        log_id: str | None = None,
        env_overrides: dict[str, str] | None = None,
        mcp_config: Path | str | None = None,
        pool_key: str | None = None,  # SDK backend only; the CLI spawns per turn
    ) -> AsyncIterator[dict[str, Any]]:
        """Run one Claude turn. Yields event dicts until the subprocess exits.

        ``session_id``, pass the value captured from a previous
        ``session_started`` event to resume a session (multi-turn). Omit
        on the first turn.

        ``allowed_tools``, list of tool names Claude is permitted to
        call. Defaults to a broad-but-safe set. Pass an empty list to
        disable all tools (useful for planning-only turns).
        """
        if not self._binary:
            yield {
                "kind": "error",
                "ts": _now_iso(),
                "message": (
                    "`claude` CLI not found on PATH. Install with "
                    "`npm install -g @anthropic-ai/claude-code` or see "
                    "https://docs.anthropic.com/en/docs/claude-code"
                ),
            }
            return

        cwd_path = Path(cwd).resolve()
        if not cwd_path.exists():
            yield {"kind": "error", "ts": _now_iso(),
                   "message": f"cwd does not exist: {cwd_path}"}
            return

        # Build the argv
        args: list[str] = [
            self._binary,
            "--print", user_prompt,
            "--output-format", "stream-json",
            "--verbose",
            "--model", model or self.config.model,
        ]
        if dangerous:
            args += ["--dangerously-skip-permissions"]
        if session_id:
            args += ["--resume", session_id]
        if system_prompt_append:
            args += ["--append-system-prompt", system_prompt_append]
        if allowed_tools is not None:
            # Comma-separated list per Claude CLI contract
            args += ["--allowed-tools", ",".join(allowed_tools) if allowed_tools else ""]
        for d in (add_dirs or []):
            args += ["--add-dir", str(Path(d).resolve())]
        if mcp_config:
            # MCP servers configured in Settings -> AI (e.g. a ServiceNow MCP).
            args += ["--mcp-config", str(Path(mcp_config).resolve())]
        args += self.config.extra_args

        # Debug-log the spawn (argv gets sanitized, append-system-prompt is truncated).
        if log_id:
            debug_logger.log(
                log_id,
                "subprocess_spawning",
                argv=args,
                cwd=str(cwd_path),
                session_id=session_id,
                model=model or self.config.model,
                prompt_chars=len(user_prompt),
            )

        # Spawn
        spawn_start = asyncio.get_event_loop().time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                cwd=str(cwd_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Don't pipe stdin, we don't use interactive input in this
                # mode; Claude reads the prompt from --print.
                stdin=asyncio.subprocess.DEVNULL,
                # env_overrides lets one agent route to a different
                # Anthropic-compatible endpoint (e.g. Ollama for a local
                # model) without touching the rest of the team.
                env={**os.environ, **agent_env(env_overrides)},
                # Bump the per-line stdout buffer, stream-json events can
                # contain file reads / Bash outputs much larger than the
                # default 64 KB. See RunnerConfig.stdout_line_limit.
                limit=self.config.stdout_line_limit,
            )
        except OSError as e:
            if log_id:
                debug_logger.log(log_id, "subprocess_spawn_failed", error=str(e))
            yield {"kind": "error", "ts": _now_iso(),
                   "message": f"failed to spawn claude: {e}"}
            return

        if log_id:
            debug_logger.log(
                log_id,
                "subprocess_spawned",
                pid=proc.pid,
            )

        # Drain stdout line-by-line, parse as stream-json.
        # A watchdog task enforces the per-turn timeout.
        assert proc.stdout is not None
        total_bytes = 0
        session_started_emitted_id: str | None = None
        pending_tool_calls: dict[str, dict[str, Any]] = {}

        async def _read_loop() -> AsyncIterator[dict[str, Any]]:
            nonlocal total_bytes, session_started_emitted_id
            while True:
                try:
                    line = await proc.stdout.readline()
                except asyncio.LimitOverrunError as e:
                    # Line exceeded our (already generous) limit. Drain
                    # what we can, log it, skip the oversized line, and
                    # keep reading, losing one fat event beats aborting
                    # the whole turn.
                    try:
                        # Consume the oversized payload so the buffer is
                        # released. readuntil raises again if we hit
                        # another separator mid-drain; keep looping.
                        oversized = await proc.stdout.read(e.consumed)
                        dropped_preview = oversized[:512].decode("utf-8", errors="replace")
                    except Exception:
                        dropped_preview = ""
                    yield {
                        "kind": "error",
                        "ts": _now_iso(),
                        "message": (
                            f"dropped one oversized stream-json line "
                            f"(>{self.config.stdout_line_limit} bytes); continuing. "
                            f"First 512 chars: {dropped_preview!r}"
                        ),
                    }
                    continue
                except Exception as e:  # noqa: BLE001
                    yield {"kind": "error", "ts": _now_iso(),
                           "message": f"stdout read failed: {e}"}
                    return
                if not line:
                    return  # EOF
                total_bytes += len(line)
                if total_bytes > self.config.max_output_bytes:
                    yield {"kind": "error", "ts": _now_iso(),
                           "message": f"output exceeded {self.config.max_output_bytes} bytes, killing"}
                    proc.kill()
                    return
                line_text = line.decode("utf-8", errors="replace").strip()
                if not line_text:
                    continue
                try:
                    payload = json.loads(line_text)
                except json.JSONDecodeError:
                    # Non-JSON line (shouldn't happen with stream-json but
                    # protect against Claude printing warnings). Skip.
                    continue
                for ev in _translate_event(payload, pending_tool_calls):
                    # Capture the session_id from the first init event we
                    # see, and short-circuit duplicate emissions.
                    if ev["kind"] == "session_started":
                        if session_started_emitted_id == ev.get("session_id"):
                            continue
                        session_started_emitted_id = ev.get("session_id")
                    yield ev

        # Everything below must guarantee the subprocess is reaped if the
        # consumer closes this generator early — e.g. the operator hits
        # Stop and the orchestrator breaks out of `async for event in
        # run_turn(...)`. Without the finally, GeneratorExit unwinds past
        # the spawn and the `claude` process orphans, continuing to run
        # tools and keep writing files after the human said stop.
        try:
            # Apply the overall timeout via wait_for on the entire read loop
            try:
                async for ev in _with_timeout(_read_loop(), self.config.timeout_s):
                    yield ev
            except asyncio.TimeoutError:
                yield {"kind": "error", "ts": _now_iso(),
                       "message": f"turn exceeded {self.config.timeout_s}s, killing subprocess"}
                proc.kill()
                await proc.wait()
                return

            # Drain stderr for diagnostic purposes
            try:
                stderr_bytes = await proc.stderr.read() if proc.stderr else b""
            except Exception:
                stderr_bytes = b""
            rc = await proc.wait()

            spawn_end = asyncio.get_event_loop().time()
            stderr_text = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

            if log_id:
                debug_logger.log(
                    log_id,
                    "subprocess_exited",
                    pid=proc.pid,
                    exit_code=rc,
                    duration_s=round(spawn_end - spawn_start, 3),
                    stdout_bytes=total_bytes,
                    stderr_chars=len(stderr_text),
                    stderr_tail=stderr_text[-2000:] if stderr_text else "",
                )

            if rc != 0 and stderr_text:
                yield {
                    "kind": "error",
                    "ts": _now_iso(),
                    "message": f"claude exited {rc}: {stderr_text[:2000]}",
                }
        finally:
            # Reap on any early exit (operator stop, cancellation, break).
            if proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                    if log_id:
                        debug_logger.log(log_id, "subprocess_killed_on_close", pid=proc.pid)
                except ProcessLookupError:
                    pass


# ── Event translation ────────────────────────────────────────────────

_SILENT_EVENT_TYPES = frozenset({"system", "rate_limit_event"})

def _translate_event(
    payload: dict[str, Any],
    pending_tool_calls: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Turn one stream-json object into 0+ of our canonical events.

    A single ``assistant`` message may contain multiple content blocks
    (thinking + tool_use + text), we emit one event per block.
    """
    out: list[dict[str, Any]] = []
    t = payload.get("type")

    if t == "system" and payload.get("subtype") == "init":
        out.append({
            "kind": "session_started",
            "ts": _now_iso(),
            "session_id": payload.get("session_id"),
            "model": payload.get("model"),
            "cwd": payload.get("cwd"),
            "tools": payload.get("tools") or [],
        })
        return out

    if t == "assistant":
        msg = payload.get("message") or {}
        for block in (msg.get("content") or []):
            btype = block.get("type")
            if btype == "text":
                text = block.get("text") or ""
                if text:
                    out.append({"kind": "text", "ts": _now_iso(), "text": text})
            elif btype == "thinking":
                text = block.get("thinking") or block.get("text") or ""
                if text:
                    out.append({"kind": "thinking", "ts": _now_iso(), "text": text})
            elif btype == "tool_use":
                tool_id = block.get("id") or ""
                tool_name = block.get("name") or "?"
                tool_input = block.get("input") or {}
                preview = _summarize_tool_input(tool_name, tool_input)
                pending_tool_calls[tool_id] = {"tool": tool_name, "input": tool_input}
                out.append({
                    "kind": "tool_call",
                    "ts": _now_iso(),
                    "tool_id": tool_id,
                    "tool_name": tool_name,
                    "input": tool_input,
                    "input_preview": preview,
                })
        if msg.get("stop_reason") == "refusal":
            out.append({"kind": "refusal", "ts": _now_iso(),
                        "model": msg.get("model"),
                        "message": "model returned stop_reason=refusal"})
        return out

    if t == "user":
        # tool_results come wrapped as a user message with content blocks
        msg = payload.get("message") or {}
        for block in (msg.get("content") or []):
            if block.get("type") != "tool_result":
                continue
            tool_use_id = block.get("tool_use_id") or ""
            content = block.get("content")
            is_error = bool(block.get("is_error"))
            preview = _summarize_tool_result(content)
            prior = pending_tool_calls.pop(tool_use_id, None)
            out.append({
                "kind": "tool_result",
                "ts": _now_iso(),
                "tool_id": tool_use_id,
                "tool_name": (prior or {}).get("tool"),
                "is_error": is_error,
                "result_preview": preview,
            })
        return out

    if t == "result":
        out.append({
            "kind": "session_complete",
            "ts": _now_iso(),
            "subtype": payload.get("subtype"),
            "cost_usd": payload.get("total_cost_usd") or payload.get("cost_usd"),
            "duration_ms": payload.get("duration_ms"),
            "num_turns": payload.get("num_turns"),
            "result": payload.get("result"),
            "session_id": payload.get("session_id"),
            "is_error": bool(payload.get("is_error")),
        })
        if payload.get("stop_reason") == "refusal":
            out.append({"kind": "refusal", "ts": _now_iso(),
                        "message": "result stop_reason=refusal"})
        return out

    # Housekeeping streams (system hook/status messages, rate-limit
    # pings) are noise in the triage stream. They stay in the debug log
    # (subprocess_event) only.
    if t in _SILENT_EVENT_TYPES:
        return out

    # Unknown event type, keep it for debugging
    out.append({"kind": "raw", "ts": _now_iso(), "type": t, "payload": payload})
    return out


def _summarize_tool_input(tool: str, inp: dict[str, Any]) -> str:
    """Short human-readable description of a tool invocation.

    Dashboard renders this inline. Keep it under ~120 chars.
    """
    if tool == "Read":
        path = inp.get("file_path") or inp.get("path") or "?"
        ol = inp.get("offset") or inp.get("limit")
        extra = f" (lines {inp.get('offset', '?')}..{inp.get('limit', '?')})" if ol else ""
        return f"Read('{_abbrev(path, 90)}'){extra}"
    if tool == "Write":
        return f"Write('{_abbrev(inp.get('file_path') or '?', 90)}')"
    if tool == "Edit":
        return f"Edit('{_abbrev(inp.get('file_path') or '?', 90)}')"
    if tool == "Glob":
        return f"Glob({_abbrev(inp.get('pattern') or '?', 60)})"
    if tool == "Grep":
        parts = [f"pattern={_abbrev(str(inp.get('pattern')), 60)}"]
        if inp.get("path"):
            parts.append(f"path={_abbrev(str(inp['path']), 40)}")
        if inp.get("glob"):
            parts.append(f"glob={inp['glob']}")
        return f"Grep({', '.join(parts)})"
    if tool == "Bash":
        cmd = inp.get("command") or ""
        return f"Bash({_abbrev(cmd, 100)})"
    if tool == "Task":
        agent = inp.get("subagent_type") or "?"
        desc = inp.get("description") or ""
        # ASCII arrow. Windows cp1252 consoles choke on U+2192.
        return f"Task -> {agent}: {_abbrev(desc, 70)}"
    if tool == "WebFetch":
        return f"WebFetch({_abbrev(inp.get('url') or '?', 90)})"
    if tool == "WebSearch":
        return f"WebSearch({_abbrev(str(inp.get('query') or '?'), 80)})"
    # Fallback
    return f"{tool}({_abbrev(json.dumps(inp, default=str), 100)})"


def _summarize_tool_result(content: Any) -> str:
    if content is None:
        return "(empty)"
    if isinstance(content, list):
        # Often content is a list of {type:'text', text:'...'} blocks
        texts: list[str] = []
        for c in content:
            if isinstance(c, dict):
                texts.append(str(c.get("text") or c.get("content") or ""))
            else:
                texts.append(str(c))
        joined = " ".join(t for t in texts if t).strip()
        return _abbrev(joined, 220) if joined else "(empty)"
    if isinstance(content, str):
        return _abbrev(content, 220)
    return _abbrev(json.dumps(content, default=str), 220)


def _abbrev(s: str, n: int) -> str:
    if not s:
        return ""
    s = s.replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


# ── Helper: timeout wrapper around an async generator ────────────────

async def _with_timeout(
    agen: AsyncIterator[dict[str, Any]],
    timeout_s: float,
) -> AsyncIterator[dict[str, Any]]:
    """Yield from ``agen`` but cap the total wall-clock time.

    The caller gets partial output even if the generator never returns,
    we stop yielding once the deadline passes and raise TimeoutError so
    the caller can cleanup the subprocess.
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_s
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError()
        try:
            ev = await asyncio.wait_for(agen.__anext__(), timeout=remaining)
        except StopAsyncIteration:
            return
        yield ev
