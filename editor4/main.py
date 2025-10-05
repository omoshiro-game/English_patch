# main.py
import frida
import sys
import time
import os
from pathlib import Path

TARGET = "Editor_v1020.exe"
AGENT_NAME = "agent.js"

def find_agent_path(name: str) -> Path:
    """
    Resolve agent.js from (in order):
      1) AGENT_PATH env var (absolute path or relative to CWD)
      2) Current working directory
      3) Folder of the executable (when frozen)
      4) PyInstaller onefile temp dir (sys._MEIPASS)
      5) Folder of this Python file (when running from source)
    Returns a Path or raises FileNotFoundError.
    """
    candidates = []

    # 1) Env override
    env_override = os.environ.get("AGENT_PATH")
    if env_override:
        candidates.append(Path(env_override))

    # 2) CWD
    candidates.append(Path.cwd() / name)

    # 3) Next to the EXE when frozen
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).parent / name)

    # 4) PyInstaller MEIPASS (one-file extraction dir)
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / name)

    # 5) Next to this script (developer runs)
    if "__file__" in globals():
        candidates.append(Path(__file__).resolve().parent / name)

    for p in candidates:
        if p and p.exists():
            return p

    raise FileNotFoundError(
        "agent.js not found. Looked in:\n  " + "\n  ".join(map(str, candidates))
    )

def on_message(message, data):
    t = message.get("type")
    if t == "send":
        print("[Agent]", message.get("payload"))
    elif t == "error":
        print("[Agent ERROR]", message.get("stack") or message, file=sys.stderr)
    else:
        print("[Agent MSG]", message)

def main():
    agent_path = find_agent_path(AGENT_NAME)
    with open(agent_path, "r", encoding="utf-8") as f:
        agent_src = f.read()

    # Spawn suspended, give the loader a moment (helps with KernelBase forwards)
    pid = frida.spawn([TARGET])
    session = frida.attach(pid)
    time.sleep(0.5)

    script = session.create_script(agent_src)
    script.on("message", on_message)
    script.load()

    frida.resume(pid)

    print("[*] Injected. Press Ctrl+C to quit.")
    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass

if __name__ == "__main__":
    main()
