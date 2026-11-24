import fsp from "node:fs/promises";
import path from "node:path";
import { entropy } from "../lib/util.js";

function cvss(sev) {
  return {
    high: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    medium: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    low: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
  }[sev];
}

function strings(buf, min = 5) {
  const out = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i += 1) {
    const b = buf[i];
    const printable = b >= 0x20 && b < 0x7f;
    if (printable && start < 0) start = i;
    if ((!printable || i === buf.length) && start >= 0) {
      if (i - start >= min) out.push(buf.toString("latin1", start, i));
      start = -1;
    }
  }
  return out;
}

function u16(buf, off, le) {
  return le ? buf.readUInt16LE(off) : buf.readUInt16BE(off);
}
function u32(buf, off, le) {
  return le ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
}
function u64(buf, off, le) {
  return Number(le ? buf.readBigUInt64LE(off) : buf.readBigUInt64BE(off));
}

function analyzeElf(buf, add) {
  const is64 = buf[4] === 2;
  const le = buf[5] === 1;
  const type = u16(buf, 16, le);
  const phoff = is64 ? u64(buf, 32, le) : u32(buf, 28, le);
  const phentsize = u16(buf, is64 ? 54 : 42, le);
  const phnum = u16(buf, is64 ? 56 : 44, le);
  let nx = true;
  let relro = false;
  let wx = false;
  let interp = false;
  for (let i = 0; i < phnum && i < 128; i += 1) {
    const off = phoff + i * phentsize;
    if (off + 8 > buf.length) break;
    const ptype = u32(buf, off, le);
    const flags = is64 ? u32(buf, off + 4, le) : u32(buf, off + 24, le);
    if (ptype === 0x6474e551) nx = !(flags & 1);
    if (ptype === 0x6474e552) relro = true;
    if (ptype === 3) interp = true;
    if ((flags & 3) === 3) wx = true;
  }
  const all = strings(buf);
  const text = all.join("\n");
  const bindNow = /BIND_NOW|FLAGS_1/.test(text) || all.some((s) => s === "BIND_NOW");
  const canary = text.includes("__stack_chk_fail");
  const fortify = /__\w+_chk\b/.test(text);
  const stripped = !text.includes(".symtab");
  const debug = /\.debug_(?:info|line|str)/.test(text);
  if (type !== 3) {
    add({
      ruleId: "elf-no-pie",
      title: "ELF binary is not position-independent",
      description: "ET_EXEC binaries load at fixed addresses, weakening ASLR.",
      severity: "medium", confidence: "high", cwe: "CWE-119", tags: ["hardening"],
      evidence: { elfType: type },
      remediation: "Compile and link with `-fPIE -pie`.",
    });
  }
  if (!nx) {
    add({
      ruleId: "elf-exec-stack",
      title: "Executable stack (NX disabled)",
      description: "The GNU_STACK segment is executable, so injected shellcode can run from the stack.",
      severity: "high", confidence: "high", cwe: "CWE-119", tags: ["hardening"],
      evidence: { nx },
      remediation: "Link with `-z noexecstack`.",
    });
  }
  if (!relro) {
    add({
      ruleId: "elf-no-relro",
      title: "No RELRO segment",
      description: "GOT entries remain writable after relocation.",
      severity: "medium", confidence: "high", cwe: "CWE-119", tags: ["hardening"],
      evidence: { relro },
      remediation: "Link with `-Wl,-z,relro,-z,now`.",
    });
  } else if (!bindNow) {
    add({
      ruleId: "elf-partial-relro",
      title: "Partial RELRO only",
      description: "The GOT is writable until lazy binding completes; full RELRO closes the window.",
      severity: "low", confidence: "high", cwe: "CWE-119", tags: ["hardening"],
      evidence: { bindNow },
      remediation: "Link with `-Wl,-z,now`.",
    });
  }
  if (wx) {
    add({
      ruleId: "elf-wx-segment",
      title: "Writable and executable segment",
      description: "A W+X mapping allows self-modifying code and easier exploitation.",
      severity: "low", confidence: "high", cwe: "CWE-119", tags: ["hardening"],
      evidence: { wx },
      remediation: "Split text and data or use `-z separate-code`.",
    });
  }
  if (!canary) {
    add({
      ruleId: "elf-no-canary",
      title: "No stack canary",
      description: "The binary does not reference __stack_chk_fail.",
      severity: "medium", confidence: "high", cwe: "CWE-121", tags: ["hardening"],
      evidence: { canary },
      remediation: "Compile with `-fstack-protector-strong`.",
    });
  }
  if (!fortify) {
    add({
      ruleId: "elf-no-fortify",
      title: "No fortified libc calls",
      description: "No `_chk` wrappers were found; bounds checks are likely absent.",
      severity: "low", confidence: "medium", cwe: "CWE-120", tags: ["hardening"],
      evidence: { fortify },
      remediation: "Compile with `-D_FORTIFY_SOURCE=3 -O2`.",
    });
  }
  if (!stripped && !debug) {
    add({
      ruleId: "elf-symbols",
      title: "Symbol table present without debug info",
      description: "Symbols ease reverse engineering and gadget discovery.",
      severity: "info", confidence: "high", cwe: "CWE-200", tags: ["hardening"],
      evidence: { stripped, debug },
      remediation: "Strip release binaries and archive separate debug symbols.",
    });
  }
  if (interp) {
    add({
      ruleId: "elf-interpreter",
      title: "Dynamic interpreter present",
      description: "The binary depends on a loader path from the build environment.",
      severity: "info", confidence: "high", cwe: "CWE-1104", tags: ["hardening"],
      evidence: { interp },
      remediation: "Use a matching runtime or build statically where practical.",
    });
  }
}

function analyzePe(buf, add) {
  const peOff = u32(buf, 0x3c, true);
  if (peOff + 24 > buf.length) return;
  const coff = peOff + 4;
  const characteristics = u16(buf, coff + 18, true);
  const optOff = coff + 20;
  const magic = u16(buf, optOff, true);
  const dllChar = u16(buf, optOff + 70, true);
  const checks = [
    [0x40, "pe-no-aslr", "ASLR disabled", "DYNAMIC_BASE is not set.", "medium", "Link with `/DYNAMICBASE`."],
    [0x100, "pe-no-dep", "DEP/NX disabled", "NX_COMPAT is not set.", "high", "Link with `/NXCOMPAT`."],
    [0x4000, "pe-no-cfg", "Control Flow Guard disabled", "GUARD_CF is not set.", "medium", "Enable `/guard:cf`."],
    [0x400, "pe-no-seh", "SEH metadata absent", "NO_SEH is set.", "low", "Keep structured exception handling enabled."],
    [0x80, "pe-no-integrity", "Image integrity check absent", "FORCE_INTEGRITY is not set.", "low", "Sign the image and set the integrity flag."],
  ];
  for (const [bit, rule, title, desc, sev, fix] of checks) {
    if (!(dllChar & bit)) {
      add({
        ruleId: rule, title, description: desc, severity: sev, confidence: "high",
        cwe: "CWE-693", tags: ["hardening"], evidence: { dllCharacteristics: dllChar, magic },
        remediation: fix,
      });
    }
  }
  if (characteristics & 0x0001) {
    add({
      ruleId: "pe-relocs-stripped",
      title: "Base relocations stripped",
      description: "The image cannot be rebased, which defeats ASLR.",
      severity: "medium", confidence: "high", cwe: "CWE-693", tags: ["hardening"],
      evidence: { characteristics },
      remediation: "Do not link with `/FIXED`.",
    });
  }
  if (!(characteristics & 0x0020)) {
    add({
      ruleId: "pe-no-large-address",
      title: "Large address aware not set",
      description: "32-bit images cannot use the full address space.",
      severity: "info", confidence: "high", cwe: "CWE-1104", tags: ["hardening"],
      evidence: { characteristics },
      remediation: "Set `/LARGEADDRESSAWARE`.",
    });
  }
}

function analyzeMachO(buf, add) {
  const le = buf.readUInt32LE(0) === 0xfeedface || buf.readUInt32LE(0) === 0xfeedfacf;
  const is64 = (le ? buf.readUInt32LE(0) : buf.readUInt32BE(0)) === 0xfeedfacf;
  const flags = u32(buf, 24, le);
  if (!(flags & 0x200000)) {
    add({
      ruleId: "macho-no-pie",
      title: "Mach-O binary is not PIE",
      description: "MH_PIE is not set, so ASLR is weakened.",
      severity: "medium", confidence: "high", cwe: "CWE-119", tags: ["hardening"],
      evidence: { flags },
      remediation: "Link with `-pie`.",
    });
  }
  if (flags & 0x20000) {
    add({
      ruleId: "macho-exec-stack",
      title: "Executable stack allowed",
      description: "MH_ALLOW_STACK_EXECUTION is set.",
      severity: "medium", confidence: "high", cwe: "CWE-119", tags: ["hardening"],
      evidence: { flags },
      remediation: "Remove `-allow_stack_execute`.",
    });
  }
  if (!(flags & 0x1000000)) {
    add({
      ruleId: "macho-no-heap-exec",
      title: "Heap execution not explicitly disabled",
      description: "MH_NO_HEAP_EXECUTION is not set.",
      severity: "low", confidence: "medium", cwe: "CWE-119", tags: ["hardening"],
      evidence: { flags },
      remediation: "Link with `-no_heap_execution` where supported.",
    });
  }
}

export default {
  id: "binary",
  name: "Binary Hardening Analyst",
  description: "ELF/PE/Mach-O hardening flags, dangerous imports and embedded credential strings.",
  category: "binary",
  targetTypes: ["binary", "code", "mixed"],
  cost: "low",
  async run(ctx) {
    let count = 0;
    for (const file of ctx.files) {
      let buf;
      try {
        buf = await fsp.readFile(file.abs);
      } catch {
        continue;
      }
      if (buf.length < 64) continue;
      const isElf = buf[0] === 0x7f && buf.toString("latin1", 1, 4) === "ELF";
      const isPe = buf[0] === 0x4d && buf[1] === 0x5a;
      const magic = buf.readUInt32LE(0);
      const isMach = [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(magic);
      if (!isElf && !isPe && !isMach) continue;
      count += 1;
      ctx.addAsset("binary", file.rel, { size: file.size, format: isElf ? "ELF" : isPe ? "PE" : "Mach-O" });
      const add = (raw) => ctx.add({
        engine: "binary",
        file: file.rel,
        line: 1,
        snippet: path.basename(file.rel),
        owasp: "A06:2021",
        cvssVector: cvss(raw.severity),
        references: [`https://cwe.mitre.org/data/definitions/${String(raw.cwe).replace("CWE-", "")}.html`],
        ...raw,
      });
      if (isElf) analyzeElf(buf, add);
      else if (isPe) analyzePe(buf, add);
      else analyzeMachO(buf, add);

      const text = strings(buf, 6).join("\n");
      const dangerous = [
        ["strcpy", "CWE-120", "strcpy has no bounds parameter."],
        ["strcat", "CWE-120", "strcat has no bounds parameter."],
        ["sprintf", "CWE-120", "sprintf has no output bound."],
        ["gets", "CWE-242", "gets cannot bound input."],
        ["system", "CWE-78", "system invokes a shell."],
        ["WinExec", "CWE-78", "WinExec invokes a shell command."],
        ["LoadLibraryA", "CWE-426", "DLL search order can be hijacked."],
      ];
      for (const [fn, cwe, desc] of dangerous) {
        if (new RegExp(`\\b${fn}\\b`).test(text)) {
          add({
            ruleId: `dangerous-import-${fn}`,
            title: `Dangerous import: ${fn}`,
            description: desc,
            severity: fn === "gets" ? "medium" : "low",
            confidence: "medium",
            cwe,
            tags: ["imports"],
            evidence: { symbol: fn },
            remediation: "Prefer bounded variants (strncpy_s, snprintf, fgets) and verify lengths.",
          });
        }
      }
      const secretPatterns = [
        [/AKIA[0-9A-Z]{16}/, "AWS access key"],
        [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "Private key"],
        [/gh[pousr]_[A-Za-z0-9]{30,}/, "GitHub token"],
        [/sk-(?:proj-)?[A-Za-z0-9_-]{20,}/, "OpenAI key"],
        [/postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@/, "Database URI"],
      ];
      for (const [re, label] of secretPatterns) {
        const m = text.match(re);
        if (m) {
          add({
            ruleId: "binary-embedded-secret",
            title: `Embedded credential string: ${label}`,
            description: "A credential-like literal is embedded in the binary and readable with `strings`.",
            severity: "medium", confidence: "medium", cwe: "CWE-798", tags: ["secret"],
            evidence: { match: m[0].slice(0, 120), entropy: Math.round(entropy(m[0]) * 10) / 10 },
            remediation: "Move the secret to runtime configuration or a secret manager.",
          });
        }
      }
      if (/\/home\/[^/\s]+\/|\/Users\/[^/\s]+\/|[A-Z]:\\\\Users\\\\[^\\\\\s]+/i.test(text)) {
        add({
          ruleId: "binary-build-path",
          title: "Build path disclosure",
          description: "Absolute developer paths remain in the binary.",
          severity: "info", confidence: "high", cwe: "CWE-200", tags: ["fingerprint"],
          evidence: { sample: text.match(/\/home\/[^/\s]+\/|\/Users\/[^/\s]+\/|[A-Z]:\\\\Users\\\\[^\\\\\s]+/i)?.[0] },
          remediation: "Use reproducible builds with remapped paths.",
        });
      }
    }
    ctx.emit("info", `Analyzed ${count} native binaries`);
  },
};
