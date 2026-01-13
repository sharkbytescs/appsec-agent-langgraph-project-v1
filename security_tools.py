# tools/security_tools.py

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from langchain_core.tools import tool

# --- General Utility Tool ---


@tool
def read_file(filepath: str) -> str:
    """
    Reads and returns the content of any single file in the project.
    Use this when you need the full context of a specific file identified by an agent.
    """
    try:
        if not os.path.exists(filepath):
            return f"Error: File not found at {filepath}"

        # Simple read, assuming UTF-8
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file {filepath}: {e}"


def prepare_codebase(input1: str) -> str:
    """
    Resolves input1 into a local project root directory.

    - If input1 is an existing local directory path: returns the absolute path.
    - If input1 is a GitHub URL (HTTPS) or git SSH URL: clones it into AI_WORKSPACE and returns the clone path.

    Returns:
        str: Absolute local filesystem path to the project root, or an error string.
    """
    try:
        input1 = (input1 or "").strip()
        if not input1:
            return "Error: input1 is empty."

        workspace = os.getenv("AI_WORKSPACE")
        if not workspace:
            return "Error: AI_WORKSPACE is not set. Add it to your .env."

        ws_path = Path(workspace).expanduser().resolve()
        ws_path.mkdir(parents=True, exist_ok=True)

        # Local path?
        p = Path(input1).expanduser()
        if p.exists():
            project_root = p.resolve()
            if not project_root.is_dir():
                return (
                    f"Error: Local path exists but is not a directory: {project_root}"
                )
            return str(project_root)

        # Otherwise treat as git URL
        if not _looks_like_git_url(input1):
            return f"Error: Input is neither an existing path nor a recognized git URL: {input1}"

        repo_name = _repo_name_from_url(input1)
        target_dir = ws_path / repo_name

        # Fresh clone to avoid stale state
        if target_dir.exists():
            shutil.rmtree(target_dir)

        cmd = ["git", "clone", "--depth", "1", input1, str(target_dir)]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return (
                "Error: git clone failed.\n"
                f"cmd: {' '.join(cmd)}\n"
                f"stdout: {result.stdout}\n"
                f"stderr: {result.stderr}"
            )

        return str(target_dir.resolve())

    except Exception as e:
        return f"Error: prepare_codebase exception: {e}"


def _looks_like_git_url(s: str) -> bool:
    if s.startswith(("http://", "https://")):
        u = urlparse(s)
        return bool(u.netloc) and "github.com" in u.netloc and u.path.count("/") >= 2
    if s.startswith("git@") and ":" in s:
        return True
    return s.endswith(".git")


def _repo_name_from_url(url: str) -> str:
    tail = url.rstrip("/").split("/")[-1]
    if url.startswith("git@") and ":" in url:
        tail = url.split(":")[-1].split("/")[-1]
    name = tail[:-4] if tail.endswith(".git") else tail
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")
    if not name:
        raise ValueError(f"Could not derive repo name from URL: {url}")
    return name


# --- SAST Tool (Semgrep) ---


@tool
def run_semgrep_sast(
    config_file: str = "p/security-audit",
    target_path: str = ".",
    language: Optional[str] = None,
) -> str:
    """
    Executes a Semgrep SAST scan on the project codebase using specified rules.

    Args:
        config_file (str): The Semgrep rule configuration (e.g., 'p/python', 'p/secrets', or a custom file path).
                           The default 'p/security-audit' is a good starting point.
        target_path (str): The directory or file to scan (defaults to the current directory).
        language (str, optional): The target programming language (e.g., 'python', 'javascript'). Semgrep often infers this.

    Returns:
        str: The raw JSON output of the Semgrep scan, or an error message.
    """
    try:
        # Build the command
        command_parts = ["semgrep", "--config", config_file, target_path, "--json"]
        if language:
            command_parts.extend(["--lang", language])

        command = " ".join(command_parts)

        # Execute the command
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=120
        )

        # Semgrep returns 0 on success, 1 on finding issues—both are acceptable outcomes
        if result.returncode in [0, 1]:
            return result.stdout
        else:
            return f"Semgrep Error (Code {result.returncode}): {result.stderr.strip()}"

    except FileNotFoundError:
        return "Error: 'semgrep' command not found. Ensure Semgrep is installed and in your system PATH."
    except Exception as e:
        return f"An exception occurred during Semgrep execution: {e}"


# --- SCA Tool (OWASP Dependency Check) ---


@tool
def run_dependency_check_sca(project_name: str, target_path: str = ".") -> str:
    """
    Executes OWASP Dependency Check (SCA) to find vulnerable dependencies.

    Args:
        project_name (str): A name for the project (e.g., 'my-app').
        target_path (str): The directory to scan (defaults to the current directory).

    Returns:
        str: The raw JSON report output, or an error message.
    """
    # Create a temporary output file path for the report
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
        output_filepath = tmp_file.name

    try:
        # Dependency Check command to output JSON to the directory of the temp file
        # The tool requires the output *directory* to be specified, not the filename
        output_dir = os.path.dirname(output_filepath)
        command = f"dependency-check --scan {target_path} --project {project_name} --format JSON --out {output_dir}"

        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,  # Long timeout for database update and deep analysis
        )

        # Dependency Check usually returns 0 (even with findings)
        if result.returncode == 0:
            # The tool creates a file named 'dependency-check-report.json' in the output directory
            report_name = "dependency-check-report.json"
            final_report_path = os.path.join(output_dir, report_name)

            if os.path.exists(final_report_path):
                with open(final_report_path, "r", encoding="utf-8") as f:
                    json_report = f.read()
                return json_report
            else:
                return f"Dependency Check ran, but the expected report file '{report_name}' was not found in '{output_dir}'."
        else:
            return f"OWASP Dependency Check Error (Code {result.returncode}): {result.stderr.strip()}"

    except FileNotFoundError:
        return "Error: 'dependency-check' command not found. Ensure the tool is installed and in your system PATH."
    except Exception as e:
        return f"An exception occurred during Dependency Check execution: {e}"
    finally:
        # Clean up the temporary file (important for a clean system)
        report_name = "dependency-check-report.json"
        final_report_path = os.path.join(os.path.dirname(output_filepath), report_name)
        if os.path.exists(final_report_path):
            os.remove(final_report_path)
        # Also clean up the original temporary file object (though mostly empty)
        if os.path.exists(output_filepath):
            os.remove(output_filepath)
