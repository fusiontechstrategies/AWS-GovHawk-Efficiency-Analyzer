"""Execute actual smoke shell steps with a harmless shadowing wheel."""

import base64
import contextlib
import csv
import hashlib
import io
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


def shell_step(name):
    workflow = Path(__file__).parents[1] / ".github/workflows/release.yml"
    lines = workflow.read_text().splitlines()
    index = lines.index("      - name: " + name) + 1
    while lines[index].strip() != "run: |":
        index += 1
    result = []
    for line in lines[index + 1 :]:
        if line and not line.startswith("          "):
            break
        result.append(line[10:] if line else "")
    return "\n".join(result)


@unittest.skipUnless(sys.platform == "linux" and Path("/usr/bin/bwrap").is_file(), "Linux system bubblewrap fixture")
class ReleaseSandboxBoundary(unittest.TestCase):
    def test_selected_wheel_script_cannot_choose_the_system_sandbox(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory, contextlib.ExitStack() as resources:
            root = Path(directory)
            socket_path = root / "host-control.sock"
            control_socket = resources.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
            control_socket.bind(str(socket_path))
            control_socket.listen(2)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control_client:
                control_client.connect(str(socket_path))
            files = {
                "boundary_fixture.py": (
                    "import os, socket\n"
                    "def main():\n    print('SHADOWED_SANDBOX')\n"
                    "def verify_boundary():\n"
                    "    assert 'SANDBOX_HOST_SECRET' not in os.environ\n"
                    "    assert not os.path.exists('/run/docker.sock')\n"
                    "    assert not os.path.exists('/var/run/docker.sock')\n"
                    "    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                    "    try:\n"
                    f"        client.connect({str(socket_path)!r})\n"
                    "    except (FileNotFoundError, PermissionError):\n        pass\n"
                    "    else:\n        raise AssertionError('host socket exposed to pth')\n"
                    "    os.environ['SANDBOX_PTH_CHECKED'] = '1'\n"
                ).encode(),
                "boundary_fixture.pth": (
                    b"import sys, boundary_fixture; boundary_fixture.verify_boundary() "
                    b"if sys.prefix == '/runtime' else None\n"
                ),
                "boundary_fixture-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: boundary-fixture\nVersion: 1.0\n",
                "boundary_fixture-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                "boundary_fixture-1.0.dist-info/entry_points.txt": b"[console_scripts]\nbwrap = boundary_fixture:main\n",
            }
            record = io.StringIO()
            writer = csv.writer(record)
            for name, value in files.items():
                digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).decode().rstrip("=")
                writer.writerow((name, "sha256=" + digest, str(len(value))))
            writer.writerow(("boundary_fixture-1.0.dist-info/RECORD", "", ""))
            files["boundary_fixture-1.0.dist-info/RECORD"] = record.getvalue().encode()
            wheel = root / "boundary_fixture-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                for name, value in files.items():
                    archive.writestr(name, value)
            (root / "runtime-lock.txt").write_text(
                "boundary-fixture==1.0 --hash=sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest() + "\n"
            )
            environment = os.environ.copy()
            environment.update(
                GITHUB_ENV=str(root / "captured-env"),
                PIP_NO_INDEX="1",
                PIP_FIND_LINKS=str(root),
                RELEASE_VERSION="0",
                SANDBOX_HOST_SECRET="synthetic-private-environment",
            )
            capture = shell_step("Install isolated runtime test sandbox")
            # Tool installation occurs in the fixture image. Execute the actual
            # workflow capture code without issuing sudo/apt from a test.
            capture = "\n".join(line for line in capture.splitlines() if not line.startswith("sudo apt-get"))
            completed = subprocess.run(
                [shutil.which("bash"), "-euo", "pipefail", "-c", capture],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            for line in (root / "captured-env").read_text().splitlines():
                key, value = line.split("=", 1)
                environment[key] = value
            # Install only the harmless fixture into a separate control venv.
            # Its executable proves the real PATH-shadowing attack primitive.
            control = root / "shadow-control"
            subprocess.run([sys.executable, "-I", "-m", "venv", str(control)], check=True, capture_output=True)
            subprocess.run(
                [
                    str(control / "bin/python"),
                    "-I",
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--only-binary=:all:",
                    "--require-hashes",
                    "-r",
                    "runtime-lock.txt",
                ],
                cwd=root,
                env=environment,
                check=True,
                capture_output=True,
            )
            environment["PATH"] = str(control / "bin") + os.pathsep + environment["PATH"]
            completed = subprocess.run(
                [
                    shutil.which("bash"),
                    "-euo",
                    "pipefail",
                    "-c",
                    shell_step("Install exact hash-locked smoke runtime dependencies"),
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode:
                if os.environ.get("REQUIRE_NATIVE_SANDBOX") == "1":
                    self.fail("Required native installation sandbox failed: " + completed.stderr)
                self.assertIn("bwrap:", completed.stderr)
                self.assertTrue(
                    any(
                        message in completed.stderr
                        for message in (
                            "Operation not permitted",
                            "No permissions to create a new namespace",
                            "Creating new namespace failed",
                        )
                    ),
                    completed.stderr,
                )
            shadow = subprocess.run(
                [str(control / "bin/bwrap"), "--version"],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(shadow.stdout.strip(), "SHADOWED_SANDBOX")
            launcher = subprocess.run(
                [environment["SMOKE_SANDBOX_PATH"], "--version"],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(launcher.returncode, 0, launcher.stderr)
            self.assertIn("bubblewrap", launcher.stdout.lower())
            assets = root / "release-assets"
            assets.mkdir()
            (assets / "AWS-GovHawk-Efficiency-Analyzer-v0.py").write_text(
                "import os, socket, sys\n"
                "assert 'SANDBOX_HOST_SECRET' not in os.environ\n"
                "assert os.environ.get('SANDBOX_PTH_CHECKED') == '1'\n"
                "assert not os.path.exists('/run/docker.sock')\n"
                "assert not os.path.exists('/var/run/docker.sock')\n"
                "client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                "try:\n"
                f"    client.connect({str(socket_path)!r})\n"
                "except (FileNotFoundError, PermissionError):\n    pass\n"
                "else:\n    raise AssertionError('host control socket exposed')\n"
                'if "--version" in sys.argv: print("GovHawk 0")\n'
            )
            exercise = subprocess.run(
                [shutil.which("bash"), "-euo", "pipefail", "-c", shell_step("Exercise the exact standalone runtime")],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotIn("SHADOWED_SANDBOX", exercise.stdout + exercise.stderr)
            # Restricted containers can deny namespace creation. That is a real
            # system launcher failure, never success supplied by the shadow.
            if exercise.returncode:
                if os.environ.get("REQUIRE_NATIVE_SANDBOX") == "1":
                    self.fail("Required native socket/environment isolation failed: " + exercise.stderr)
                self.assertIn("bwrap:", exercise.stderr)
                self.assertTrue(
                    any(
                        message in exercise.stderr
                        for message in (
                            "Operation not permitted",
                            "No permissions to create a new namespace",
                            "Creating new namespace failed",
                        )
                    ),
                    exercise.stderr,
                )
            self.assertEqual(
                hashlib.sha256(Path(environment["SMOKE_SANDBOX_PATH"]).read_bytes()).hexdigest(),
                environment["SMOKE_SANDBOX_SHA256"],
            )


if __name__ == "__main__":
    unittest.main()
