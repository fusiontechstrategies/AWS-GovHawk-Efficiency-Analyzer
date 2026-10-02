"""Actual Windows retained-handle attacks in owned disposable fixtures only."""

import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import AWS_GovCloud_Analyzer as app


@unittest.skipUnless(os.name == "nt", "Native Windows relative filesystem operations")
class NativeReportPublication(unittest.TestCase):
    def test_initially_empty_parent_reparse_cannot_redirect_staging(self):
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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = app.windows_private_report_directory(root, app.current_windows_sid())
            target = root / "redirected"
            target.mkdir()
            sentinel = target / "keep"
            sentinel.write_bytes(b"untouched")
            substitute = ("\\??\\" + str(target)).encode("utf-16-le")
            printable = str(target).encode("utf-16-le")
            names = substitute + b"\0\0" + printable + b"\0\0"
            request = (
                struct.pack(
                    "<IHHHHHH", 0xA0000003, 8 + len(names), 0, 0, len(substitute), len(substitute) + 2, len(printable)
                )
                + names
            )
            buffer = ctypes.create_string_buffer(request)
            returned = wintypes.DWORD()
            writer = kernel.CreateFileW(str(parent), 0x102, 7, None, 3, 0x02200000, None)
            self.assertNotEqual(writer, ctypes.c_void_p(-1).value)
            opened = app.windows_relative_report_open
            attacked = []

            def before_create(handle, name, **options):
                if options.get("create") and options.get("directory") and name.startswith(".govhawk-private-"):
                    self.assertEqual(attacked, [])
                    self.assertTrue(
                        kernel.DeviceIoControl(
                            writer, 0x900A4, buffer, len(request), None, 0, ctypes.byref(returned), None
                        ),
                        ctypes.get_last_error(),
                    )
                    attacked.append(True)
                return opened(handle, name, **options)

            try:
                with patch.object(app, "windows_relative_report_open", side_effect=before_create):
                    with self.assertRaises((PermissionError, OSError)):
                        with app.private_report_file(parent / "report.json"):
                            self.fail("Reparsed parent reached content writing")
                self.assertEqual(attacked, [True])
                self.assertEqual(list(target.iterdir()), [sentinel])
                self.assertEqual(sentinel.read_bytes(), b"untouched")
            finally:
                if attacked:
                    deletion = ctypes.create_string_buffer(struct.pack("<IHH", 0xA0000003, 0, 0))
                    self.assertTrue(
                        kernel.DeviceIoControl(writer, 0x900AC, deletion, 8, None, 0, ctypes.byref(returned), None),
                        ctypes.get_last_error(),
                    )
                kernel.CloseHandle(writer)
            self.assertEqual(list(parent.iterdir()), [])
            parent.rmdir()

    def test_native_publication_no_overwrite_and_short_unicode_names(self):
        for name in ("x", "é.json", "report.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory) / "reports"
                output = parent / name
                with app.private_report_file(output) as stream:
                    stream.write(b"original")
                with self.assertRaises(FileExistsError):
                    with app.private_report_file(output) as stream:
                        stream.write(b"replacement")
                self.assertEqual(output.read_bytes(), b"original")
                self.assertEqual(list(parent.iterdir()), [output])

    def test_windows_pipeline_never_uses_pathname_open_link_or_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new-parent" / "report.json"
            with (
                patch.object(app.os, "open", side_effect=AssertionError("pathname file open")),
                patch.object(app.os, "link", side_effect=AssertionError("pathname publication")),
                patch.object(Path, "unlink", side_effect=AssertionError("pathname cleanup")),
            ):
                with app.private_report_file(output) as stream:
                    stream.write(b"handle bound")
            self.assertEqual(output.read_bytes(), b"handle bound")
            self.assertEqual(list(output.parent.iterdir()), [output])


if __name__ == "__main__":
    unittest.main()
