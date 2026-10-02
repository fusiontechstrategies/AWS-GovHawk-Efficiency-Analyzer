"""Offline descriptor ACL, native sharing and diagnostic privacy checks."""

import ast
import ctypes
import io
import json
import logging
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import AWS_GovCloud_Analyzer as app


class AclLogFollowups(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "Linux descriptor ACL semantics")
    def test_actual_named_posix_acl_is_refused_before_report_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "private"
            parent.mkdir(mode=0o700)
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                app.verify_posix_report_acl(fd)
                acl = struct.pack("<I", 2) + b"".join(
                    struct.pack("<HHI", tag, rights, uid)
                    for tag, rights, uid in (
                        (1, 7, 0xFFFFFFFF),
                        (2, 4, 31337),
                        (4, 0, 0xFFFFFFFF),
                        (16, 4, 0xFFFFFFFF),
                        (32, 0, 0xFFFFFFFF),
                    )
                )
                os.setxattr(fd, "system.posix_acl_access", acl)
                self.assertTrue(os.getxattr(fd, "system.posix_acl_access"))
                self.assertFalse(os.fstat(fd).st_mode & 0o022)
                with self.assertRaisesRegex(PermissionError, "extended ACL"):
                    with app.private_report_file(parent / "report.json"):
                        self.fail("Unsafe ACL reached content write")
                self.assertEqual(list(parent.iterdir()), [])
            finally:
                os.close(fd)

    @unittest.skipUnless(sys.platform == "linux", "Linux filesystem inspection")
    def test_unverified_filesystem_and_acl_inspection_failure_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                app.verify_posix_report_acl(fd)
                fake = MagicMock()

                def unsupported(_fd, output):
                    ctypes.cast(output, ctypes.POINTER(ctypes.c_long))[0] = 0x6969
                    return 0

                fake.fstatfs.side_effect = unsupported
                with patch.object(ctypes, "CDLL", return_value=fake):
                    with self.assertRaisesRegex(PermissionError, "unverified ACL"):
                        app.verify_posix_report_acl(fd)
                with patch.object(os, "getxattr", side_effect=PermissionError()):
                    with self.assertRaisesRegex(PermissionError, "Cannot establish"):
                        app.verify_posix_report_acl(fd)
            finally:
                os.close(fd)

    def test_unsupported_posix_platform_refused(self):
        with patch.object(sys, "platform", "darwin"):
            with self.assertRaisesRegex(PermissionError, "supported local Linux"):
                app.verify_posix_report_acl(-1)

    @unittest.skipUnless(os.name == "nt", "Native Win32 sharing and reparse semantics")
    def test_protected_child_blocks_preauthorized_directory_reparse(self):
        import ctypes.wintypes

        wintypes = ctypes.wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.DeviceIoControl.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        kernel.DeviceIoControl.restype = wintypes.BOOL
        invalid = ctypes.c_void_p(-1).value
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "synthetic-target"
            target.mkdir()
            substitute = ("\\??\\" + str(target)).encode("utf-16-le")
            printable = str(target).encode("utf-16-le")
            paths = substitute + b"\x00\x00" + printable + b"\x00\x00"
            request = (
                struct.pack(
                    "<IHHHHHH", 0xA0000003, 8 + len(paths), 0, 0, len(substitute), len(substitute) + 2, len(printable)
                )
                + paths
            )
            buffer = ctypes.create_string_buffer(request)
            returned = wintypes.DWORD()

            def reparse(handle):
                return kernel.DeviceIoControl(
                    handle, 0x900A4, buffer, len(request), None, 0, ctypes.byref(returned), None
                )

            control = root / "empty-control"
            control.mkdir()
            handle = kernel.CreateFileW(str(control), 0x102, 7, None, 3, 0x02000000, None)
            self.assertNotEqual(handle, invalid)
            try:
                self.assertTrue(reparse(handle), ctypes.get_last_error())
            finally:
                kernel.CloseHandle(handle)
                control.rmdir()

            parent = app.windows_private_report_directory(root, app.current_windows_sid())
            writer = kernel.CreateFileW(str(parent), 0x102, 7, None, 3, 0x02000000, None)
            self.assertNotEqual(writer, invalid)
            try:
                output = parent / "report.json"
                with app.private_report_file(output) as stream:
                    child = next(parent.iterdir())
                    with self.assertRaises(PermissionError):
                        child.rename(parent / "replacement-child")
                    self.assertFalse(reparse(writer))
                    self.assertEqual(ctypes.get_last_error(), 145)
                    stream.write(b"protected synthetic report")
                self.assertEqual(output.read_bytes(), b"protected synthetic report")
            finally:
                kernel.CloseHandle(writer)
                for leaf in parent.iterdir():
                    leaf.unlink()
                parent.rmdir()

    def test_resource_debug_events_have_no_interpolated_identifiers(self):
        tree = ast.parse(Path(app.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "debug":
                self.assertIsInstance(node.args[0], ast.Constant)

    @unittest.skipUnless(os.name == "nt", "Windows final authorization recheck")
    def test_changed_authorization_aborts_before_link_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = app.windows_private_report_directory(Path(directory), app.current_windows_sid())
            mutation = None
            try:
                with self.assertRaisesRegex(PermissionError, "synthetic changed ACL"):
                    with app.private_report_file(parent / "report.json") as stream:
                        stream.write(b"synthetic report")
                        mutation = patch.object(
                            app, "verify_windows_parent_security", side_effect=PermissionError("synthetic changed ACL")
                        )
                        mutation.start()
                self.assertEqual(list(parent.iterdir()), [])
            finally:
                if mutation is not None:
                    mutation.stop()
                parent.rmdir()

    def test_local_and_json_diagnostics_drop_paths_identifiers_and_tracebacks(self):
        marker = "arn:aws-us-gov:iam::123456789012:role/private vpc-secret C:\\private user\\report.pdf /home/private/logo.png person@example.test"
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        app.logger.addHandler(handler)
        try:
            app.logger.warning("Synthetic diagnostic %s", marker, stack_info=True)
            record = logging.LogRecord(
                "govhawk",
                logging.ERROR,
                "",
                0,
                "Synthetic diagnostic %s",
                (marker,),
                (ValueError, ValueError(marker), None),
            )
            formatted = json.loads(app.JsonLogFormatter().format(record))
            for text in (output.getvalue(), formatted["message"]):
                for private in ("123456789012", "vpc-secret", "private", "person@", "Stack"):
                    self.assertNotIn(private, text)
                self.assertIn("Synthetic diagnostic", text)
        finally:
            app.logger.removeHandler(handler)
            handler.close()

    def test_pr_checkouts_do_not_persist_tokens(self):
        workflow = (Path(app.__file__).parent / ".github/workflows/ci.yml").read_text()
        for checkout in workflow.split("uses: actions/checkout@")[1:]:
            self.assertIn("persist-credentials: false", checkout.split("- name:", 1)[0])
