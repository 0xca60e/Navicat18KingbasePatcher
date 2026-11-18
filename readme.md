# Navicat 18 KingbaseES Connection Patcher

Fixes the handshake failure that occurs when Navicat 18 connects to a KingbaseES
(Ren Da Jin Cang) database — `SHOW enable_upper_colname` fails with
"unrecognized configuration parameter".

The patch site is **located** (locate-then-patch) rather than hard-coded, so it
works with any Navicat 18 build.

---

## Table of Contents

- [Symptoms](#symptoms)
- [Root Cause](#root-cause)
- [How the Patch Works](#how-the-patch-works)
- [Requirements](#requirements)
- [Usage](#usage)
- [Command-Line Arguments](#command-line-arguments)
- [How the Patch Site Is Located](#how-the-patch-site-is-located)
- [Caveats](#caveats)

---

## Symptoms

When you create a KingbaseES connection in Navicat 18 and test the connection,
the connection is aborted during the handshake phase, and the log/dialog shows:

```
ERROR: unrecognized configuration parameter "enable_upper_colname"
```

This error is unrelated to the username, password, IP address, or port you
entered. Navicat 18 sends the client a statement that KingbaseES does not
support, and **the failure of that single statement is treated as a failure of
the entire connection handshake**.

---

## Root Cause

In `CSObjectConnAction_PGSQL::acquireConnectedSession` (the connection
handshake routine of the PG family), the KingbaseES branch
(`serviceProvider == 0x0E`) ends like this:

```asm
        ...
        jmp   L2                  ; <-- the bug: jumps over the reload
    L1: mov   r14d, [rsp+0x34]    ; r14d = accumulated error code (v169)
    L2: mov   eax, r14d           ; <- the function's return value
        ...
```

Because this `jmp` skips the `mov r14d, [rsp+0x34]` at `L1`, the register `eax`
still holds `r14d` — that is, the **error code of the `SHOW
enable_upper_colname` statement**. That error code is therefore returned
directly as the function's return value, and the handshake is aborted.

Every earlier statement in the same function follows the "accumulate the error
code into `[rsp+0x34]`" pattern, and the function ultimately returns that
accumulated value. When the KingbaseES branch is entered, that accumulated
value is provably 0 (the only path into the branch is the fall-through where
`v169 = v5`, and the guard requires `v5 == 0`; the other paths are skipped
because `v5 != 0`).

---

## How the Patch Works

Let the KingbaseES branch fall through to the reload as well, i.e. change the
jump target from "the instruction after the reload" to "the reload itself":

```
Before:  eb 05   44 8b 74 24 34   41 8b c6      ; jmp +5 -> skips the reload
After:   eb 00   44 8b 74 24 34   41 8b c6      ; jmp +0 -> lands on the reload
```

| Instruction | Bytes | Meaning |
| --- | --- | --- |
| `jmp rel8` | `eb 05` → `eb 00` | The jump displacement changes from +5 to 0 |
| `mov r14, [rsp+0x34]` | `44 8b 74 24 34` | Reload of the accumulated error code (not modified) |
| `mov eax, r14d` | `41 8b c6` | Return value (not modified) |

The patch changes exactly 1 byte (`0x05` → `0x00`), and only applies when the
`jmp` uses the 2-byte `rel8` encoding; for the 5-byte `rel32` encoding, the
4-byte displacement field is rewritten to 0 instead.

After the fix, a failure of `SHOW enable_upper_colname` only means that the
"column-name case flag" is not updated, instead of failing the whole
connection — exactly the same `if (err) skip` behavior as the other statements
in the function.

---

## Requirements

| Item | Requirement |
| --- | --- |
| Operating system | Windows (Navicat 18 supports Windows / macOS / Linux; this script targets the Windows `libcc.dll`) |
| Python | 3.9 or newer (development/verification environment: Python 3.12.7, 64-bit) |
| Dependencies | `numpy`, `capstone` |

Install the dependencies:

```bash
pip install numpy capstone
```

---

## Usage

The script has three actions: `verify` (detect only), `apply` (patch), and
`revert` (restore).

### 1. Locate Navicat's libcc.dll

The usual path is:

```
C:\Program Files\Navicat Premium 18\libcc.dll
```

Other common install locations:

```
C:\Program Files\Navicat 18\libcc.dll
C:\Program Files\PremiumSoft\Navicat Premium 18\libcc.dll
```

If you use a portable/unzipped version, it is in the root of the extracted
directory.

> It is recommended to **fully quit** Navicat first (including the tray icon)
> so that `libcc.dll` is not locked before running any write operation.

### 2. Verify first, then patch

```bash
# Detect only, do not modify any file
python -I patch_navicat18_kingbase.py verify "C:\Program Files\Navicat Premium 18\libcc.dll"
```

The output `NEEDS PATCH` means the current file has the defect; the output
`ALREADY PATCHED / OK` means no action is needed.

### 3. Apply the patch

```bash
# Modify in place
python -I patch_navicat18_kingbase.py apply "C:\Program Files\Navicat Premium 18\libcc.dll"

# Or write to a new file, leaving the original untouched (recommended)
python -I patch_navicat18_kingbase.py apply "C:\Program Files\Navicat Premium 18\libcc.dll" --out "C:\temp\libcc.patched.dll"
```

### 4. Revert the patch

```bash
python -I patch_navicat18_kingbase.py revert "C:\Program Files\Navicat Premium 18\libcc.dll"
```

Reverting restores the jump displacement to the length of the skipped
instruction (i.e. `eb 05`), returning to the original buggy behavior.

### 5. Strip the digital signature in one go (optional)

If you want Navicat to start without the "cannot verify digital signature"
prompt, you can also clear the PE's Authenticode security directory:

```bash
python -I patch_navicat18_kingbase.py apply "C:\Program Files\Navicat Premium 18\libcc.dll" --strip-signature
```

---

## Command-Line Arguments

```
python -I patch_navicat18_kingbase.py verify <dll>
python -I patch_navicat18_kingbase.py apply  <dll> [--out FILE] [--strip-signature] [--no-checksum]
python -I patch_navicat18_kingbase.py revert <dll> [--out FILE] [--strip-signature] [--no-checksum]
```

| Argument | Description |
| --- | --- |
| `verify` | Locates the patch site and reports its state only, **writes no files**, exit code 0 |
| `apply` | Turns the jump into a fall-through, fixing the defect |
| `revert` | Restores the jump to "skip the reload", reinstating the defect |
| `--out FILE` | Writes the result to `FILE`, leaving `<dll>` untouched. Without it, the file is overwritten in place |
| `--strip-signature` | Zeroes the Security Directory (index 4) in the PE Optional Header so Windows no longer validates the Authenticode signature. The certificate data blob is still kept in the file; only the pointer to it is cleared |
| `--no-checksum` | Does not recompute the PE checksum; instead the CheckSum field is set to 0 directly (Windows ignores that field when loading anyway) |

When running `apply` / `revert`, the script **recomputes the PE checksum**
(using the standard Windows folded-sum algorithm, skipping the CheckSum field
itself and adding the file length), and prints the values before and after.

> Note: `apply` / `revert` rewrite the file even when "no change is needed"
> (only the checksum is updated). If you need byte-for-byte consistency of the
> file, back it up first or use `--out`.

---

## How the Patch Site Is Located

The script does not rely on any hard-coded offset. Instead, it *finds* the
defect in the binary in the following order:

1. **Anchor**: search the `.rdata` section for the literal
   `SHOW enable_upper_colname` and obtain its RVA.
2. **References**: scan `.text` with a vectorized NumPy search to find all
   instructions that reference that string via RIP-relative addressing.
3. **Function ownership**: use `.pdata` (the x64 runtime function table) with a
   binary search to place each reference in the `[start, end)` range of its
   containing function.
4. **Instruction-level matching**: use Capstone to disassemble those functions
   and look for the following "epilogue shape" — a `jmp` that skips exactly one
   `mov rXd, [rsp+disp]`, followed by `mov eax, rXd`:

   ```asm
       jmp   L2
   L1: mov rXd, [rsp+disp]
   L2: mov eax, rXd
   ```

   A jump target equal to the address of `mov eax, rXd` means **buggy**; a jump
   target equal to the address of `mov rXd, [rsp+disp]` means **ok** (already
   fixed).
5. **Independent cross-check**: run a separate search over the **entire file**
   using the raw byte signature and require that both methods locate
   **exactly the same address**; otherwise the run is treated as a failure and
   aborted (without modifying anything).
6. **Semantic check**: confirm that the stack slot `[rsp+disp]` read by the
   skipped instruction really does have a write site inside the same function
   (i.e. it is the "accumulated error code" slot); otherwise a warning is
   printed.

If any step does not succeed (anchor not found, multiple candidates found,
the two methods disagreeing on the address), the script prints an error and
exits with code 1, **without modifying the file**.

---

## Caveats

- **Back up `libcc.dll` first**. The script does not create a backup file
  automatically.
- **The patch is invalidated by a Navicat upgrade**, because `libcc.dll` is
  replaced wholesale. Run `verify` again on the new version.
- The patch only affects the handshake behavior of the KingbaseES branch. It
  **does not change any database objects and does not bypass any licensing or
  encryption checks** — it only downgrades "one optional statement failed" from
  "the connection failed" to "skip that flag".
- `--strip-signature` makes the file no longer carry a verifiable Authenticode
  signature (the certificate block is still inside the file, but Windows no
  longer validates it). This is a normal side effect of binary modification.
- The `verify` action is read-only and can safely be used on any Navicat
  installation directory.

---
