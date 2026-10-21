# Hermes Whisper.cpp local STT

This module makes the already-working Kikin Kushi Whisper.cpp command provider
reproducible. Hermes and Whisper.cpp execute on Kikin Kushi; Hermes files may
reside on X230-backed NFS storage without changing the execution host. Live
Telegram ingress has already been user-confirmed. This module does not require
another ingress test, cross-host provisioning, a gateway restart, or a config
redesign.

## Pinned assets

- Model: `ggerganov/whisper.cpp` `ggml-small.bin`
- Upstream revision: `5359861c739e955e79d9a303bcbc70fb988958b1`
- Size: `487601967` bytes
- SHA-256: `1be3a9b2063867b937e64e2ec7483364a79917e157fa98c5d94b5c1fffea987b`
- Runtime contract: existing `whisper-cli` version `1.9.1`
- Pinned download: the installer uses the revision above, never floating
  `main`, and only accesses the network when `--download` is explicit.

The installer verifies the runtime and the full model size and SHA-256 before
writing destination files. It does not install packages, edit Hermes config,
enable STT, select a cloud fallback, restart a gateway, or modify the existing
faster-whisper wrapper.

## Isolated offline install, second run, and check

Use the existing Guix runtime and the already-verified persistent model as an
offline source. Choose a disposable root outside the live paths:

```bash
repo=/home/metsatron/DotCortex-wt-kikin/hermes-local-stt-reliability-20261021
installer="$repo/linux/.local/bin/hermes-stt-whispercpp-install"
runtime=/home/metsatron/.guix-extra-profiles/inference/inference/bin/whisper-cli
model_source=/home/metsatron/.local/share/hermes-stt/models/ggml-small.bin
# Select the physical path explicitly when a scratch alias contains symlinks.
root=$(realpath -m /home/metsatron/.hermes/cache/scratch/hermes-stt-parent-check)

"$installer" --install \
  --prefix "$root/prefix" \
  --data-home "$root/data" \
  --scratch "$root/scratch" \
  --runtime "$runtime" \
  --model-source "$model_source"

# The second install must preserve bytes and mtimes.
"$installer" --install \
  --prefix "$root/prefix" \
  --data-home "$root/data" \
  --scratch "$root/scratch" \
  --runtime "$runtime" \
  --model-source "$model_source"

# Check mode is read-only and does not require --model-source.
"$installer" --check \
  --prefix "$root/prefix" \
  --data-home "$root/data" \
  --runtime "$runtime"
```

For a fresh acquisition, replace `--model-source "$model_source"` with
`--download`. The download is staged under `--scratch`, validated in full, and
only then atomically installed.

Repeated offline installs preserve installed bytes and mtimes. Repeating
`--download` currently reacquires the source and therefore still needs network
access, even when installed files are valid. Use read-only `--check` for an
offline health check; this limitation does not alter a valid installation.

## Invoke the isolated adapter

```bash
adapter="$root/prefix/bin/hermes-stt-whispercpp"
input=/absolute/path/to/audio.wav
output="$root/transcript.txt"
"$adapter" "$input" "$output" small auto
```

The adapter refuses to overwrite an existing transcript. Remove or choose a
new output path deliberately before repeating an invocation.

## Isolated Hermes config example

The following is a template for a disposable `HERMES_HOME`; do not merge it
into the active config as part of provisioning:

```yaml
stt:
  provider: whispercpp
  providers:
    whispercpp:
      type: command
      command: "/absolute/scratch/prefix/bin/hermes-stt-whispercpp {input_path} {output_path} {model} {language}"
      format: txt
      model: small
      language: auto
      timeout: 300
```

An explicit provider selection fails locally when its adapter, runtime, or
model is unavailable; this procedure does not configure a cloud fallback.

## Recovery and rollback

- The installer refuses symlink destinations, non-files, unexpected bytes,
  corrupt models, and unexpected permissions instead of replacing them.
- Both install and check reject symlinks in any adapter/model destination
  component, including roots and existing parent directories. Supply an
  explicitly chosen physical path, not a symlink alias. This is a preflight
  check for operator-controlled roots, not protection against another process
  maliciously replacing directories during installation.
- File replacement is atomic and file contents are fsynced. The two-file
  installation is not transactional or a claim of full power-loss durability;
  after interruption, inspect the files and rerun install/check. Keep the
  canonical source and pinned provenance backed up separately from model data.
- Preserve and inspect an unexpected destination before removing it. After the
  operator has identified it, move it to a backup path and rerun the installer.
- A disposable installation rolls back by removing only its chosen `--prefix`,
  `--data-home`, and `--scratch` roots.
- A future live deployment must back up the live adapter first and must not
  touch `/home/metsatron/.local/bin/hermes-local-stt`.
- The existing Guix inference profile provisions `whisper-cli`; this helper
  verifies that runtime but does not claim to provision it on a fresh OS.
