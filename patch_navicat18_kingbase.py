"""Patch Navicat 18's libcc.dll so the new "SHOW enable_upper_colname" step cannot
fail a KingbaseES connection.

The patch site is LOCATED, not hard-coded, so the same script works on any Navicat 18
build.

------------------------------------------------------------------------------
What is being fixed
------------------------------------------------------------------------------
In CSObjectConnAction_PGSQL::acquireConnectedSession (the PG-family connection
handshake) the KingbaseES branch (serviceProvider == 0x0E) ends like this:

        ...
        jmp   L2                  ; <-- the bug: jumps over the reload
    L1: mov   r14d, [rsp+0x34]    ; r14d = accumulated error (v169)
    L2: mov   eax, r14d           ; <- function's return value
        ...

Because of the jump, `eax` keeps r14d = the error code of the "SHOW
enable_upper_colname" statement, so that code becomes the function's return value.
A server-side ERROR (e.g. "unrecognized configuration parameter
\"enable_upper_colname\"") therefore aborts the connection.

Every older statement in the same function feeds its error into the accumulated
variable at [rsp+0x34] and the function returns that instead.  When the Kingbase
branch is entered that accumulated value is provably 0 (the only path into the
branch is the fall-through where v169 = v5 and the guard requires v5 == 0; the
other paths arrive with v5 != 0 and are skipped).

Fix: make the Kingbase branch fall through to the reload as well, i.e. change the
jump so its target is the `mov rXd, [rsp+...]` instruction instead of the one
after it.  The statement's failure then only skips the column-name flag update
instead of failing the connection - exactly the `if (err) skip` behaviour of the
older statements.

------------------------------------------------------------------------------
How the site is located (in order)
------------------------------------------------------------------------------
1. Anchor: find the literal "SHOW enable_upper_colname" in .rdata.
2. Find the RIP-relative code references to it, and the .pdata function that
   contains each reference -> the candidate function(s).
3. Inside those functions, disassemble and look for the epilogue shape
       jmp  L2            (L2 == address of the `mov eax, rXd`)
       L1: mov rXd, [rsp+disp]
       L2: mov eax, rXd
   i.e. a short jump that skips exactly one `mov rXd, [rsp+...]`.
4. Cross-check with a raw byte-pattern search over the whole file; both methods
   must agree on the same address.
5. Verify that the stack slot loaded by the skipped instruction is also written
   inside the same function (the accumulated-error slot).

Usage
-----
    python -I patch_navicat18_kingbase.py verify <dll>
    python -I patch_navicat18_kingbase.py apply  <dll> [--out FILE]
                                              [--strip-signature] [--no-checksum]
    python -I patch_navicat18_kingbase.py revert <dll> [--out FILE]
                                              [--strip-signature] [--no-checksum]

With --out the patched result is written to FILE and <dll> is left untouched.
"""
import bisect
import hashlib
import struct
import sys

import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_EAX, X86_REG_RIP, X86_REG_RSP

ANCHOR_STRING = b"SHOW enable_upper_colname"

# raw byte signature of the same site, used as an independent cross-check
BYTE_SIG = bytes.fromhex("eb05448b74243441" "8bc6")          # unpatched
BYTE_SIG_PATCHED = bytes.fromhex("eb00448b74243441" "8bc6")  # already patched


def die(msg):
    print("ERROR: " + msg)
    sys.exit(1)


# --------------------------------------------------------------------------- PE


class PE:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = bytearray(f.read())
        d = self.data
        self.pe = struct.unpack_from("<I", d, 0x3C)[0]
        nsec = struct.unpack_from("<H", d, self.pe + 6)[0]
        optsz = struct.unpack_from("<H", d, self.pe + 20)[0]
        self.imgbase = struct.unpack_from("<Q", d, self.pe + 24 + 24)[0]
        self.opt = self.pe + 24
        self.dirs = self.opt + 112
        self.sections = []
        off = self.pe + 24 + optsz
        for _ in range(nsec):
            name = d[off : off + 8].rstrip(b"\x00").decode("latin1")
            vsz, va, rsz, ptr = struct.unpack_from("<IIII", d, off + 8)
            self.sections.append({"name": name, "va": va, "vsize": vsz, "ptr": ptr, "rsize": rsz})
            off += 40

        # .pdata -> sorted runtime-function table
        self.pdata = []
        for s in self.sections:
            if s["name"] == ".pdata":
                base = s["ptr"]
                for i in range(s["rsize"] // 12):
                    b, e, _ = struct.unpack_from("<III", d, base + i * 12)
                    if b or e:
                        self.pdata.append((b, e))
                self.pdata.sort()

    def sec(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def rva_to_off(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + s["vsize"]:
                return s["ptr"] + (rva - s["va"])
        return None

    def off_to_rva(self, off):
        for s in self.sections:
            if s["ptr"] <= off < s["ptr"] + s["rsize"]:
                return s["va"] + (off - s["ptr"])
        return None

    def func_bounds(self, rva):
        j = bisect.bisect_right(self.pdata, (rva, 1 << 31)) - 1
        if j >= 0 and self.pdata[j][0] <= rva < self.pdata[j][1]:
            return self.pdata[j]
        return None

    def checksum(self):
        return struct.unpack_from("<I", self.data, self.opt + 64)[0]

    def recompute_checksum(self):
        ck_off = self.opt + 64
        saved = struct.unpack_from("<I", self.data, ck_off)[0]
        length = len(self.data)
        nw = length // 2
        words = struct.unpack_from("<%dH" % nw, self.data, 0)
        ck_word = ck_off // 2
        c = 0
        i = 0
        while i < nw:
            if i == ck_word:
                i += 2
                continue
            c = ((c & 0xFFFF) + (c >> 16)) + words[i]
            c = (c & 0xFFFF) + (c >> 16)
            i += 1
        if length & 1:
            c = ((c & 0xFFFF) + (c >> 16)) + self.data[length - 1]
            c = (c & 0xFFFF) + (c >> 16)
        c = (c & 0xFFFF) + (c >> 16)
        ck = (c + length) & 0xFFFFFFFF
        struct.pack_into("<I", self.data, ck_off, ck)
        return saved, ck

    def strip_signature(self):
        sec_off = self.dirs + 4 * 8
        rva, size = struct.unpack_from("<II", self.data, sec_off)
        if size == 0:
            return None
        struct.pack_into("<II", self.data, sec_off, 0, 0)
        return (rva, size)


# ------------------------------------------------------------------- locating


def find_anchor(pe):
    """RVA of the anchor string inside .rdata."""
    rdata = pe.sec(".rdata")
    if rdata is None:
        die("no .rdata section")
    lo = rdata["ptr"]
    hi = lo + rdata["rsize"]
    hits = []
    s = lo
    while True:
        i = pe.data.find(ANCHOR_STRING, s, hi)
        if i < 0:
            break
        hits.append(i)
        s = i + 1
    if not hits:
        die("anchor string %r not found - is this a Navicat 18 build that still "
            "issues 'SHOW enable_upper_colname'?" % ANCHOR_STRING.decode())
    return [pe.off_to_rva(h) for h in hits], hits


def rip_refs(pe, target_rva):
    """RVAs of instructions with a RIP-relative operand pointing at target_rva."""
    text = pe.sec(".text")
    buf = pe.data[text["ptr"] : text["ptr"] + text["rsize"]]
    a = np.frombuffer(bytes(buf), dtype=np.uint8)
    hits = []
    for shift in range(4):
        n = (len(a) - shift) // 4
        if n <= 0:
            continue
        w = a[shift : shift + n * 4].view(np.int32)
        disp = w.astype(np.int64)
        idx = shift + 4 * np.arange(n, dtype=np.int64)
        rva_after = idx + text["va"] + 4
        for j in np.nonzero((rva_after + disp) == target_rva)[0]:
            hits.append(int(idx[j]) + text["va"])
    return sorted(set(hits))


def find_candidates(pe, anchor_rvas):
    """Instruction-level search for the buggy epilogue inside the anchor's function."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    results = []
    anchor_funcs = set()
    for arva in anchor_rvas:
        for ref in rip_refs(pe, arva):
            b = pe.func_bounds(ref)
            if b:
                anchor_funcs.add(b)
    for (fs, fe) in sorted(anchor_funcs):
        off = pe.rva_to_off(fs)
        code = bytes(pe.data[off : off + (fe - fs)])
        insns = list(md.disasm(code, pe.imgbase + fs))
        for i in range(len(insns) - 2):
            a, b_, c = insns[i], insns[i + 1], insns[i + 2]
            # a: jmp with an immediate target
            if a.mnemonic != "jmp" or not a.operands or a.operands[0].type != X86_OP_IMM:
                continue
            # c: mov eax, rXd
            if c.mnemonic != "mov" or len(c.operands) != 2:
                continue
            if c.operands[0].type != X86_OP_REG or c.operands[0].reg != X86_REG_EAX:
                continue
            if c.operands[1].type != X86_OP_REG:
                continue
            reg = c.operands[1].reg
            # b: mov rXd, [rsp + disp]
            if b_.mnemonic != "mov" or len(b_.operands) != 2:
                continue
            if b_.operands[0].type != X86_OP_REG or b_.operands[0].reg != reg:
                continue
            if b_.operands[1].type != X86_OP_MEM:
                continue
            m = b_.operands[1].mem
            if m.base != X86_REG_RSP:
                continue
            disp = m.disp
            # the jump must skip exactly one instruction
            if b_.address != a.address + a.size:
                continue
            target = a.operands[0].imm
            if target == c.address:
                state = "buggy"      # jumps over the reload -> error code becomes the return value
            elif target == b_.address:
                state = "ok"         # falls through to the reload -> error code is accumulated
            else:
                continue
            results.append({
                "jmp_rva": a.address - pe.imgbase,
                "jmp_size": a.size,
                "disp": target,
                "skipped": b_,
                "ret_insn": c,
                "stack_disp": disp,
                "func": (fs, fe),
                "state": state,
                "already_ok": state == "ok",
            })
    return results, sorted(anchor_funcs)


def stack_slot_written(pe, fs, fe, disp):
    """True if [rsp+disp] is written somewhere inside the function (the error slot)."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    off = pe.rva_to_off(fs)
    code = bytes(pe.data[off : off + (fe - fs)])
    for ins in md.disasm(code, pe.imgbase + fs):
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            continue
        dst = ins.operands[0]
        if dst.type != X86_OP_MEM:
            continue
        if dst.mem.base != X86_REG_RSP or dst.mem.disp != disp:
            continue
        return True
    return False


def byte_pattern_sites(pe):
    """Independent cross-check: raw byte signature occurrences in the whole file."""
    out = []
    for sig, tag in ((BYTE_SIG, "unpatched"), (BYTE_SIG_PATCHED, "patched")):
        s = 0
        while True:
            i = pe.data.find(sig, s)
            if i < 0:
                break
            out.append((i, tag))
            s = i + 1
    return out


# ------------------------------------------------------------------- reporting


def disasm_snippet(pe, c, before=8, after=6):
    """Disassemble the whole function and print a window around the patch site."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    fs, fe = c["func"]
    off = pe.rva_to_off(fs)
    code = bytes(pe.data[off : off + (fe - fs)])
    insns = list(md.disasm(code, pe.imgbase + fs))
    target = pe.imgbase + c["jmp_rva"]
    idx = next((i for i, ins in enumerate(insns) if ins.address == target), None)
    if idx is None:
        return ["      (patch site not on an instruction boundary)"]
    lines = []
    for ins in insns[max(0, idx - before) : idx + after + 1]:
        mark = "   <<< patch site" if ins.address == target else ""
        lines.append("      0x%x  %-22s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic + " " + ins.op_str, mark))
    return lines


def locate(pe):
    anchor_rvas, _ = find_anchor(pe)
    cands, funcs = find_candidates(pe, anchor_rvas)
    pats = byte_pattern_sites(pe)
    print("  anchor %r at RVA %s" % (ANCHOR_STRING.decode(), [hex(a) for a in anchor_rvas]))
    print("  anchor function(s): %s" % ([("0x%x-0x%x" % f) for f in funcs] or "none"))
    print("  epilogue candidates found: %d" % len(cands))
    print("  byte-signature matches   : %d  %s" % (len(pats), [(hex(o), t) for o, t in pats]))
    if not cands:
        die("could not locate the epilogue - this build may already be fixed "
            "or differs structurally; nothing was changed")
    if len(cands) > 1:
        die("ambiguous: %d candidate sites found - nothing was changed" % len(cands))
    c = cands[0]
    want = "unpatched" if c["state"] == "buggy" else "patched"
    pat = [o for o, t in pats if t == want]
    if len(pat) != 1:
        die("byte-signature cross-check failed (%d '%s' hits) - nothing was changed" % (len(pat), want))
    if pat[0] != pe.rva_to_off(c["jmp_rva"]):
        die("byte-signature and instruction-level search disagree - nothing was changed")
    if not stack_slot_written(pe, c["func"][0], c["func"][1], c["stack_disp"]):
        print("  WARNING: stack slot [rsp+0x%x] is not written inside this function" % c["stack_disp"])
    return c


def report(pe, c):
    off = pe.rva_to_off(c["jmp_rva"])
    state = "already correct (jump falls through)" if c["already_ok"] else "BUGGY (jump skips the reload)"
    print("  patch site : file 0x%X / RVA 0x%X" % (off, c["jmp_rva"]))
    print("  state      : %s" % state)
    print("  function   : RVA 0x%x-0x%x" % c["func"])
    print("  error slot : [rsp+0x%x]" % c["stack_disp"])
    print("  disassembly:")
    for l in disasm_snippet(pe, c):
        print(l)


def apply_patch(pe, c):
    """Rewrite the jump so it targets the `mov rXd, [rsp+disp]` instruction."""
    rva = c["jmp_rva"]
    off = pe.rva_to_off(rva)
    size = c["jmp_size"]
    if size == 2:                       # rel8 jmp:  eb dd
        pe.data[off + 1] = 0
        print("  jmp rel8  : displacement -> 0 (fall through to the reload)")
    elif size == 5:                     # rel32 jmp: e9 dd dd dd dd
        struct.pack_into("<i", pe.data, off + 1, 0)
        print("  jmp rel32 : displacement -> 0 (fall through to the reload)")
    else:
        die("unexpected jmp encoding size %d" % size)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    action, path = sys.argv[1], sys.argv[2]
    outpath = None
    if "--out" in sys.argv:
        outpath = sys.argv[sys.argv.index("--out") + 1]

    pe = PE(path)
    print("== %s : %s" % (action, path))
    print("  size %d bytes, imagebase 0x%x" % (len(pe.data), pe.imgbase))
    print("  sha256 %s" % hashlib.sha256(bytes(pe.data)).hexdigest())
    c = locate(pe)
    report(pe, c)

    if action == "verify":
        print("  verdict: %s" % ("ALREADY PATCHED / OK" if c["already_ok"] else "NEEDS PATCH"))
        return 0

    if action == "apply":
        if c["already_ok"]:
            print("  nothing to do - already patched")
        else:
            apply_patch(pe, c)
    elif action == "revert":
        if not c["already_ok"]:
            print("  nothing to do - already unpatched")
        else:
            # restore the original "skip the reload" jump:
            # displacement = size of the skipped instruction, so the target is
            # the instruction right after it.
            off = pe.rva_to_off(c["jmp_rva"])
            if c["jmp_size"] == 2:
                pe.data[off + 1] = c["skipped"].size & 0xFF
            else:
                struct.pack_into("<i", pe.data, off + 1, c["skipped"].size)
            print("  jump restored to skip the reload (disp = %d)" % c["skipped"].size)
    else:
        die("unknown action %r" % action)

    if "--no-checksum" not in sys.argv:
        old, new = pe.recompute_checksum()
        if old != new:
            print("  PE checksum  0x%08X -> 0x%08X" % (old, new))
    else:
        struct.pack_into("<I", pe.data, pe.opt + 64, 0)

    if "--strip-signature" in sys.argv:
        info = pe.strip_signature()
        if info:
            print("  Authenticode: Security directory cleared (cert blob 0x%X/%d bytes kept)"
                  % (info[0], info[1]))

    target = outpath or path
    with open(target, "wb") as f:
        f.write(bytes(pe.data))
    print("  written %s%s" % (target, "" if outpath else "  (in place)"))
    if outpath:
        print("  input left untouched: %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
