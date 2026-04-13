#!/usr/bin/env python3
"""Reproduce OSWorld screenshot HTTP 500 (vs_code task).

This script faithfully replicates the exact OSWorld framework flow
for the vs_code task that crashes ~100% of the time with a real LLM
agent. The goal is to reproduce WITHOUT the LLM by matching every
detail of the real execution path.

The error: QEMU loadvm restores qcow2 snapshot, but ext4 inside the
guest detects data corruption (EBADMSG) and remounts read-only.
The screenshot server then can't write screenshot.png → HTTP 500.

Usage:
    cd /path/to/OSWorld
    python /path/to/nitrobox/examples/repro_screenshot_500.py

With LLM (guaranteed repro):
    cd /path/to/OSWorld
    rm -rf ./results_test_vscode
    ANTHROPIC_API_KEY=... python -u scripts/python/run_multienv_claude.py \\
        --provider_name nitrobox --api_provider anthropic --headless \\
        --observation_type screenshot --model claude-sonnet-4-6 \\
        --sleep_after_execution 3 --max_steps 15 --num_envs 1 \\
        --client_password password \\
        --test_all_meta_path /tmp/test_vscode_only.json \\
        --result_dir ./results_test_vscode
"""
from __future__ import annotations

import json
import os
import random
import sys
import time

import requests

# --- Configuration ---
OSWORLD_DIR = os.environ.get(
    "OSWORLD_DIR",
    os.path.join(os.path.dirname(__file__), ".."),
)
VM_PATH = os.environ.get(
    "OSWORLD_VM_PATH",
    os.path.join(OSWORLD_DIR, "docker_vm_data", "Ubuntu.qcow2"),
)
ROUNDS = int(os.environ.get("REPRO_ROUNDS", "10"))

# Exact vs_code agent trajectory (recorded from a crash run).
# Steps 1-6 always succeed, step 7 (after Ctrl+S or DONE) triggers 500.
SETUP_STEPS = [
    # 1. Upload file to VM
    ("upload", {
        "local": "vscode_replace_text.txt",
        "remote": "/home/user/Desktop/vscode_replace_text.txt",
        "content": "This is a text file with text content.\n" * 20,
    }),
    # 2. Launch VS Code with the file
    ("launch", {"command": ["code", "/home/user/Desktop/vscode_replace_text.txt"]}),
    # 3. Activate VS Code window
    ("activate", {"window_name": "Visual Studio Code"}),
    # 4. Wait for VS Code to load
    ("sleep", {"seconds": 5}),
]

AGENT_STEPS = [
    # Ctrl+H (find/replace)
    "pyautogui.keyDown('ctrl')\npyautogui.keyDown('h')\npyautogui.keyUp('h')\npyautogui.keyUp('ctrl')",
    # Click find field
    "pyautogui.click(1474, 160)",
    # Type "text"
    "pyautogui.press('t')\npyautogui.press('e')\npyautogui.press('x')\npyautogui.press('t')",
    # Click replace field
    "pyautogui.click(1474, 187)",
    # Type "test"
    "pyautogui.press('t')\npyautogui.press('e')\npyautogui.press('s')\npyautogui.press('t')",
    # Click Replace All
    "pyautogui.click(1633, 187)",
    # Ctrl+S (save) — this is where 500 typically hits
    "pyautogui.keyDown('ctrl')\npyautogui.keyDown('s')\npyautogui.keyUp('s')\npyautogui.keyUp('ctrl')",
]

PYAUTOGUI_PREFIX = "import pyautogui; import time; pyautogui.FAILSAFE = False; "


def execute_command(base_url: str, command: str) -> tuple[int, str]:
    """Execute via PythonController's exact format."""
    full_cmd = PYAUTOGUI_PREFIX + command
    r = requests.post(
        f"{base_url}/execute",
        json={"command": ["python", "-c", full_cmd], "shell": False},
        timeout=30,
    )
    body = r.json() if r.status_code == 200 else {}
    return r.status_code, body.get("output", "")


def get_screenshot(base_url: str) -> tuple[int, int, str]:
    """Mimic PythonController.get_screenshot() — 3 retries, 5s interval."""
    for attempt in range(3):
        try:
            r = requests.get(f"{base_url}/screenshot", timeout=10)
            if r.status_code == 200:
                content = r.content
                if len(content) >= 8 and content[:8] == b"\x89PNG\r\n\x1a\n":
                    return 200, len(content), ""
            return r.status_code, len(r.content), r.text[:200]
        except Exception as e:
            pass
        time.sleep(5)
    return 0, 0, "all retries failed"


def start_recording(base_url: str) -> int:
    """Start ffmpeg recording like the real framework does."""
    try:
        r = requests.post(f"{base_url}/start_recording", timeout=10)
        return r.status_code
    except:
        return -1


def stop_recording(base_url: str) -> int:
    try:
        r = requests.post(f"{base_url}/stop_recording", timeout=15)
        return r.status_code
    except:
        return -1


def check_fs_state(base_url: str) -> str:
    """Check if guest filesystem is read-only."""
    try:
        r = requests.post(f"{base_url}/execute", json={
            "command": ["bash", "-c",
                        "cat /proc/mounts | grep ' / ' | grep -oE ' rw,| ro,' | tr -d ' ,'"],
            "shell": False,
        }, timeout=5)
        return r.json().get("output", "?").strip()
    except:
        return "?"


def setup_task(base_url: str):
    """Run the vs_code task setup steps."""
    for step_type, params in SETUP_STEPS:
        if step_type == "upload":
            # Create the file on VM
            content = params["content"].replace("'", "'\\''")
            requests.post(f"{base_url}/execute", json={
                "command": ["bash", "-c",
                            f"echo '{content}' > {params['remote']}"],
                "shell": False,
            }, timeout=15)
        elif step_type == "launch":
            requests.post(
                f"{base_url}/setup/launch",
                json={"command": params["command"]},
                timeout=30,
            )
        elif step_type == "activate":
            requests.post(
                f"{base_url}/setup/activate_window",
                json={"window_name": params["window_name"]},
                timeout=15,
            )
        elif step_type == "sleep":
            time.sleep(params["seconds"])


def run_one_round(base_url: str, provider, round_idx: int) -> bool:
    """Run one complete vs_code task cycle. Returns True if 500 occurred."""
    def checkpoint(label: str) -> bool:
        """Check fs state. Returns True if ro (bad)."""
        fs = check_fs_state(base_url)
        if fs != "rw":
            print(f"    !!! {label}: fs={fs}", flush=True)
            return True
        return False

    # 1. loadvm (episode reset)
    provider.revert_to_snapshot(VM_PATH, "")
    time.sleep(2)
    if checkpoint("after loadvm"):
        return True

    # 2. Setup steps (with checkpoint after each)
    # 2a. Upload file
    content = ("This is a text file with text content.\n" * 20).replace("'", "'\\''")
    requests.post(f"{base_url}/execute", json={
        "command": ["bash", "-c",
                    f"echo '{content}' > /home/user/Desktop/vscode_replace_text.txt"],
        "shell": False,
    }, timeout=15)
    if checkpoint("after upload file"):
        return True

    # 2b. Launch VS Code
    requests.post(
        f"{base_url}/setup/launch",
        json={"command": ["code", "/home/user/Desktop/vscode_replace_text.txt"]},
        timeout=30,
    )
    time.sleep(5)
    if checkpoint("after launch vscode"):
        return True

    # 3. Start recording
    start_recording(base_url)

    # 4. Initial screenshot
    get_screenshot(base_url)

    # 5. Execute agent steps WITH screenshots
    for step_idx, cmd in enumerate(AGENT_STEPS):
        execute_command(base_url, cmd)
        time.sleep(3)
        status, size, body = get_screenshot(base_url)
        if status != 200:
            fs = check_fs_state(base_url)
            print(f"    Step {step_idx+1}: screenshot {status} fs={fs}", flush=True)
            stop_recording(base_url)
            return True
        time.sleep(8)

    stop_recording(base_url)
    return False


def main():
    sys.path.insert(0, OSWORLD_DIR)
    from desktop_env.providers.nitrobox.provider import NitroboxProvider

    provider = NitroboxProvider()
    provider.start_emulator(VM_PATH, headless=True)
    base_url = f"http://localhost:{provider.server_port}"

    # Wait for server
    for _ in range(30):
        try:
            r = requests.get(f"{base_url}/screenshot", timeout=5)
            if r.status_code == 200:
                break
        except:
            pass
        time.sleep(1)

    print(f"VM ready at {base_url}")
    print(f"Running {ROUNDS} rounds of vs_code task...\n")

    total_500 = 0
    for i in range(ROUNDS):
        got_500 = run_one_round(base_url, provider, i)
        if got_500:
            total_500 += 1
            print(f"  Round {i+1}/{ROUNDS}: FAIL (500)")
        else:
            print(f"  Round {i+1}/{ROUNDS}: OK")

    provider.stop_emulator(VM_PATH)
    print(f"\nResult: {total_500}/{ROUNDS} rounds had 500 errors")


if __name__ == "__main__":
    main()
