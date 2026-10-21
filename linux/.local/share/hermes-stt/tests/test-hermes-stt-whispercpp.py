#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import io
import importlib.machinery
import importlib.util
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
INSTALLER = ROOT / "linux/.local/bin/hermes-stt-whispercpp-install"
TEMPLATE = ROOT / "linux/.local/share/hermes-stt/hermes-stt-whispercpp.template"
MODEL_BYTES = b"fixture whisper model\n"
MODEL_SHA256 = hashlib.sha256(MODEL_BYTES).hexdigest()


def load_installer():
    loader = importlib.machinery.SourceFileLoader("hermes_stt_installer", str(INSTALLER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class HermesWhisperCppTests(unittest.TestCase):
    def test_symlinked_destination_ancestors_are_refused_before_writes(self) -> None:
        module = load_installer()
        for location in ("prefix", "data", "prefix/bin", "data/hermes-stt"):
            for children_exist in (False, True):
                with self.subTest(location=location, children_exist=children_exist):
                    with tempfile.TemporaryDirectory(prefix="hermes-stt-ancestor-") as tmp:
                        root = Path(tmp).resolve()
                        prefix, data_home = root / "prefix", root / "data"
                        runtime = root / "whisper-cli"
                        runtime.write_text(
                            "#!/bin/sh\nprintf '%s\\n' 'whisper.cpp version: 1.9.1'\n",
                            encoding="utf-8",
                        )
                        runtime.chmod(0o700)
                        source = root / "model.bin"
                        source.write_bytes(MODEL_BYTES)
                        outside = root / "outside"
                        outside.mkdir()
                        link = root / location
                        link.parent.mkdir(parents=True, exist_ok=True)
                        link.symlink_to(outside, target_is_directory=True)
                        if children_exist:
                            for child in ("bin", "hermes-stt/models", "models"):
                                (outside / child).mkdir(parents=True, exist_ok=True)
                        before = sorted(str(p.relative_to(outside)) for p in outside.rglob("*"))
                        result = module.main(
                            ["--install", "--prefix", str(prefix), "--data-home", str(data_home),
                             "--runtime", str(runtime), "--model-source", str(source)],
                            model_sha256=MODEL_SHA256, model_size=len(MODEL_BYTES),
                        )
                        self.assertNotEqual(result, 0, "symlinked destination ancestor was accepted")
                        self.assertEqual(
                            sorted(str(p.relative_to(outside)) for p in outside.rglob("*")), before,
                        )
                        self.assertFalse((prefix / "bin/hermes-stt-whispercpp").exists())
                        self.assertFalse((data_home / "hermes-stt/models/ggml-small.bin").exists())

    def test_first_install_creates_private_verified_files(self) -> None:
        module = load_installer()
        with tempfile.TemporaryDirectory(prefix="hermes stt test ") as tmp:
            root = Path(tmp)
            prefix = root / "prefix with spaces"
            data_home = root / "data with spaces"
            runtime = root / "runtime with spaces" / "whisper-cli"
            runtime.parent.mkdir()
            runtime.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' 'whisper.cpp version: 1.9.1'\n",
                encoding="utf-8",
            )
            runtime.chmod(0o700)
            model_source = root / "model source.bin"
            model_source.write_bytes(MODEL_BYTES)

            result = module.main(
                [
                    "--install",
                    "--prefix",
                    str(prefix),
                    "--data-home",
                    str(data_home),
                    "--runtime",
                    str(runtime),
                    "--model-source",
                    str(model_source),
                ],
                model_sha256=MODEL_SHA256,
                model_size=len(MODEL_BYTES),
            )

            adapter = prefix / "bin/hermes-stt-whispercpp"
            model = data_home / "hermes-stt/models/ggml-small.bin"
            self.assertEqual(result, 0)
            self.assertTrue(adapter.is_file())
            self.assertEqual(model.read_bytes(), MODEL_BYTES)
            self.assertEqual(stat.S_IMODE(adapter.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(model.stat().st_mode), 0o600)
            text = adapter.read_text(encoding="utf-8")
            self.assertIn(str(runtime), text)
            self.assertIn(str(model), text)

    def test_missing_runtime_makes_no_installation(self) -> None:
        module = load_installer()
        with tempfile.TemporaryDirectory(prefix="hermes stt missing runtime ") as tmp:
            root = Path(tmp)
            prefix = root / "prefix"
            data_home = root / "data"
            model_source = root / "model.bin"
            model_source.write_bytes(MODEL_BYTES)

            result = module.main(
                [
                    "--install",
                    "--prefix",
                    str(prefix),
                    "--data-home",
                    str(data_home),
                    "--runtime",
                    str(root / "missing-whisper-cli"),
                    "--model-source",
                    str(model_source),
                ],
                model_sha256=MODEL_SHA256,
                model_size=len(MODEL_BYTES),
            )

            self.assertNotEqual(result, 0)
            self.assertFalse(prefix.exists())
            self.assertFalse(data_home.exists())

    def test_bad_model_checksum_makes_no_installation(self) -> None:
        module = load_installer()
        with tempfile.TemporaryDirectory(prefix="hermes stt bad checksum ") as tmp:
            root = Path(tmp)
            prefix = root / "prefix"
            data_home = root / "data"
            runtime = root / "runtime" / "whisper-cli"
            runtime.parent.mkdir()
            runtime.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' 'whisper.cpp version: 1.9.1'\n",
                encoding="utf-8",
            )
            runtime.chmod(0o700)
            bad_model = root / "bad-model.bin"
            bad_model.write_bytes(b"wrong model bytes\n")

            result = module.main(
                [
                    "--install",
                    "--prefix",
                    str(prefix),
                    "--data-home",
                    str(data_home),
                    "--runtime",
                    str(runtime),
                    "--model-source",
                    str(bad_model),
                ],
                model_sha256=MODEL_SHA256,
                model_size=len(bad_model.read_bytes()),
            )

            self.assertNotEqual(result, 0)
            self.assertFalse(prefix.exists())
            self.assertFalse(data_home.exists())

    def test_download_is_explicit_and_uses_pinned_revision_url(self) -> None:
        module = load_installer()
        with tempfile.TemporaryDirectory(prefix="hermes stt download ") as tmp:
            root = Path(tmp)
            prefix = root / "prefix"
            data_home = root / "data"
            scratch = root / "scratch"
            runtime = root / "runtime" / "whisper-cli"
            runtime.parent.mkdir()
            runtime.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' 'whisper.cpp version: 1.9.1'\n",
                encoding="utf-8",
            )
            runtime.chmod(0o700)
            seen: list[str] = []

            def fake_urlopen(url: str, timeout: int):
                self.assertEqual(
                    url,
                    "https://huggingface.co/ggerganov/whisper.cpp/resolve/"
                    "5359861c739e955e79d9a303bcbc70fb988958b1/ggml-small.bin?download=true",
                )
                seen.append(url)
                return io.BytesIO(MODEL_BYTES)

            base_args = [
                "--prefix",
                str(prefix),
                "--data-home",
                str(data_home),
                "--scratch",
                str(scratch),
                "--runtime",
                str(runtime),
            ]
            self.assertNotEqual(
                module.main(
                    ["--install", *base_args],
                    model_sha256=MODEL_SHA256,
                    model_size=len(MODEL_BYTES),
                    urlopen=fake_urlopen,
                ),
                0,
            )
            self.assertEqual(seen, [])
            self.assertFalse(prefix.exists())
            self.assertFalse(data_home.exists())

            self.assertEqual(
                module.main(
                    ["--install", *base_args, "--download"],
                    model_sha256=MODEL_SHA256,
                    model_size=len(MODEL_BYTES),
                    urlopen=fake_urlopen,
                ),
                0,
            )
            self.assertEqual(seen, [module.MODEL_URL])
            self.assertIn(module.MODEL_REVISION, seen[0])
            self.assertEqual(
                (data_home / "hermes-stt/models/ggml-small.bin").read_bytes(),
                MODEL_BYTES,
            )

    def test_corrupt_destination_is_refused_before_any_write(self) -> None:
        module = load_installer()
        with tempfile.TemporaryDirectory(prefix="hermes stt corrupt destination ") as tmp:
            root = Path(tmp)
            prefix = root / "prefix"
            data_home = root / "data"
            adapter = prefix / "bin/hermes-stt-whispercpp"
            adapter.parent.mkdir(parents=True)
            adapter.write_bytes(b"operator-owned unexpected adapter\n")
            adapter.chmod(0o700)
            original = adapter.read_bytes()
            runtime = root / "runtime" / "whisper-cli"
            runtime.parent.mkdir()
            runtime.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' 'whisper.cpp version: 1.9.1'\n",
                encoding="utf-8",
            )
            runtime.chmod(0o700)
            model_source = root / "model.bin"
            model_source.write_bytes(MODEL_BYTES)

            result = module.main(
                [
                    "--install",
                    "--prefix",
                    str(prefix),
                    "--data-home",
                    str(data_home),
                    "--runtime",
                    str(runtime),
                    "--model-source",
                    str(model_source),
                ],
                model_sha256=MODEL_SHA256,
                model_size=len(MODEL_BYTES),
            )

            self.assertNotEqual(result, 0)
            self.assertEqual(adapter.read_bytes(), original)
            self.assertFalse(data_home.exists())

    def test_symlink_destination_is_refused_before_any_write(self) -> None:
        module = load_installer()
        with tempfile.TemporaryDirectory(prefix="hermes stt symlink destination ") as tmp:
            root = Path(tmp)
            prefix = root / "prefix"
            data_home = root / "data"
            runtime = root / "runtime" / "whisper-cli"
            runtime.parent.mkdir()
            runtime.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' 'whisper.cpp version: 1.9.1'\n",
                encoding="utf-8",
            )
            runtime.chmod(0o700)
            model_source = root / "model.bin"
            model_source.write_bytes(MODEL_BYTES)
            model = data_home / "hermes-stt/models/ggml-small.bin"
            adapter = prefix / "bin/hermes-stt-whispercpp"
            adapter.parent.mkdir(parents=True)
            target = root / "operator-owned-adapter"
            target.write_bytes(module.render_adapter(TEMPLATE.read_bytes(), model, runtime))
            target.chmod(0o700)
            original = target.read_bytes()
            adapter.symlink_to(target)

            result = module.main(
                [
                    "--install",
                    "--prefix",
                    str(prefix),
                    "--data-home",
                    str(data_home),
                    "--runtime",
                    str(runtime),
                    "--model-source",
                    str(model_source),
                ],
                model_sha256=MODEL_SHA256,
                model_size=len(MODEL_BYTES),
            )

            self.assertNotEqual(result, 0)
            self.assertTrue(adapter.is_symlink())
            self.assertEqual(target.read_bytes(), original)
            self.assertFalse(data_home.exists())

    def test_adapter_runs_with_space_paths(self) -> None:
        module = load_installer()
        with tempfile.TemporaryDirectory(prefix="hermes stt adapter spaces ") as tmp:
            root = Path(tmp)
            prefix = root / "prefix with spaces"
            data_home = root / "data with spaces"
            runtime = root / "runtime with spaces" / "whisper-cli"
            runtime.parent.mkdir()
            runtime.write_text(
                "#!/bin/sh\n"
                "if [ \"${1:-}\" = --version ]; then printf '%s\\n' 'whisper.cpp version: 1.9.1'; exit 0; fi\n"
                "output=''\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  case \"$1\" in --output-file) output=$2; shift 2;; *) shift;; esac\n"
                "done\n"
                "printf '%s' 'fixture transcript' >\"${output}.txt\"\n",
                encoding="utf-8",
            )
            runtime.chmod(0o700)
            model_source = root / "model source.bin"
            model_source.write_bytes(MODEL_BYTES)
            self.assertEqual(
                module.main(
                    [
                        "--install",
                        "--prefix",
                        str(prefix),
                        "--data-home",
                        str(data_home),
                        "--runtime",
                        str(runtime),
                        "--model-source",
                        str(model_source),
                    ],
                    model_sha256=MODEL_SHA256,
                    model_size=len(MODEL_BYTES),
                ),
                0,
            )
            input_path = root / "audio input.wav"
            input_path.write_bytes(b"audio")
            output_path = root / "output dir" / "transcript.txt"

            result = subprocess.run(
                [
                    str(prefix / "bin/hermes-stt-whispercpp"),
                    str(input_path),
                    str(output_path),
                    "small",
                    "",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "fixture transcript")

    def test_adapter_refuses_existing_output(self) -> None:
        module = load_installer()
        with tempfile.TemporaryDirectory(prefix="hermes stt adapter no clobber ") as tmp:
            root = Path(tmp)
            prefix = root / "prefix"
            data_home = root / "data"
            runtime = root / "runtime" / "whisper-cli"
            marker = root / "runtime-was-called"
            runtime.parent.mkdir()
            runtime.write_text(
                "#!/bin/sh\n"
                "if [ \"${1:-}\" = --version ]; then printf '%s\\n' 'whisper.cpp version: 1.9.1'; exit 0; fi\n"
                f": >'{marker}'\n"
                "exit 9\n",
                encoding="utf-8",
            )
            runtime.chmod(0o700)
            model_source = root / "model.bin"
            model_source.write_bytes(MODEL_BYTES)
            self.assertEqual(
                module.main(
                    [
                        "--install",
                        "--prefix",
                        str(prefix),
                        "--data-home",
                        str(data_home),
                        "--runtime",
                        str(runtime),
                        "--model-source",
                        str(model_source),
                    ],
                    model_sha256=MODEL_SHA256,
                    model_size=len(MODEL_BYTES),
                ),
                0,
            )
            input_path = root / "input.wav"
            input_path.write_bytes(b"audio")
            output_path = root / "transcript.txt"
            output_path.write_text("operator-owned transcript", encoding="utf-8")

            result = subprocess.run(
                [
                    str(prefix / "bin/hermes-stt-whispercpp"),
                    str(input_path),
                    str(output_path),
                    "small",
                    "en",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing to overwrite", result.stderr)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "operator-owned transcript")
            self.assertFalse(marker.exists())

    def test_second_install_and_check_preserve_bytes_and_mtimes(self) -> None:
        module = load_installer()
        with tempfile.TemporaryDirectory(prefix="hermes stt idempotent ") as tmp:
            root = Path(tmp)
            prefix = root / "prefix"
            data_home = root / "data"
            runtime = root / "runtime" / "whisper-cli"
            runtime.parent.mkdir()
            runtime.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' 'whisper.cpp version: 1.9.1'\n",
                encoding="utf-8",
            )
            runtime.chmod(0o700)
            model_source = root / "model.bin"
            model_source.write_bytes(MODEL_BYTES)
            install_args = [
                "--install",
                "--prefix",
                str(prefix),
                "--data-home",
                str(data_home),
                "--runtime",
                str(runtime),
                "--model-source",
                str(model_source),
            ]
            check_args = [
                "--check",
                "--prefix",
                str(prefix),
                "--data-home",
                str(data_home),
                "--runtime",
                str(runtime),
            ]
            self.assertEqual(
                module.main(install_args, model_sha256=MODEL_SHA256, model_size=len(MODEL_BYTES)),
                0,
            )
            adapter = prefix / "bin/hermes-stt-whispercpp"
            model = data_home / "hermes-stt/models/ggml-small.bin"
            before = {
                path: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in (adapter, model)
            }

            self.assertEqual(
                module.main(install_args, model_sha256=MODEL_SHA256, model_size=len(MODEL_BYTES)),
                0,
            )
            self.assertEqual(
                module.main(check_args, model_sha256=MODEL_SHA256, model_size=len(MODEL_BYTES)),
                0,
            )
            after = {
                path: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in (adapter, model)
            }
            self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
