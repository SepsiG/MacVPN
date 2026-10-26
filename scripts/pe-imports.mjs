#!/usr/bin/env node
// Prints the DLLs a PE file (exe or dll) imports, normal and delay-loaded, lower-case, sorted, one per line; with
// --subsystem, the optional header's Subsystem instead (2: Windows GUI, 3: console); with --machine, the COFF
// header's Machine in hex (8664: x64, aa64: ARM64).
// No dependencies: the release gates of scripts/build-msi.sh check that no crypto or SQLite DLL is imported and
// that WinVPN.exe is a GUI program (no console window) and WinVPNService.exe a console one, each for its architecture.
//
//   node scripts/pe-imports.mjs [--subsystem | --machine] FILE
import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const subsystem = args[0] === '--subsystem';
const machine = args[0] === '--machine';
if (subsystem || machine) args.shift();
if (args.length !== 1) {
  console.error('usage: pe-imports.mjs [--subsystem | --machine] FILE');
  process.exit(2);
}
const buf = readFileSync(args[0]);
if (buf.toString('latin1', 0, 2) !== 'MZ') throw new Error('not a PE file (no MZ header)');
const pe = buf.readUInt32LE(0x3c);
if (buf.toString('latin1', pe, pe + 4) !== 'PE\0\0') throw new Error('not a PE file');
const coff = pe + 4;
if (machine) {
  console.log(buf.readUInt16LE(coff).toString(16));
  process.exit(0);
}
const sectionCount = buf.readUInt16LE(coff + 2);
const optionalSize = buf.readUInt16LE(coff + 16);
const optional = coff + 20;
// PE32+ (0x20b, 64-bit) has 112 bytes before the data directories, PE32 96.
const directories = optional + (buf.readUInt16LE(optional) === 0x20b ? 112 : 96);
const sections = optional + optionalSize;
if (subsystem) {
  // At offset 68 of the optional header in PE32 and PE32+ alike.
  console.log(buf.readUInt16LE(optional + 68));
  process.exit(0);
}

/// The file offset of a relative virtual address.
function offset(rva) {
  for (let i = 0; i < sectionCount; i++) {
    const s = sections + i * 40;
    const va = buf.readUInt32LE(s + 12);
    const size = Math.max(buf.readUInt32LE(s + 8), buf.readUInt32LE(s + 16));
    if (rva >= va && rva < va + size) return rva - va + buf.readUInt32LE(s + 20);
  }
  throw new Error(`RVA ${rva} is outside every section`);
}

function cstring(at) {
  let end = at;
  while (buf[end] !== 0) end++;
  return buf.toString('latin1', at, end);
}

const names = new Set();
// Data directory 1: the import table (20-byte descriptors, the name RVA at +12, ended by a zero descriptor).
const imports = buf.readUInt32LE(directories + 1 * 8);
if (imports) {
  for (let d = offset(imports); buf.readUInt32LE(d + 12) !== 0; d += 20) {
    names.add(cstring(offset(buf.readUInt32LE(d + 12))).toLowerCase());
  }
}
// Data directory 13: the delay-load import table (32-byte descriptors, the name RVA at +4).
const delayed = buf.readUInt32LE(directories + 13 * 8);
if (delayed) {
  for (let d = offset(delayed); buf.readUInt32LE(d + 4) !== 0; d += 32) {
    names.add(cstring(offset(buf.readUInt32LE(d + 4))).toLowerCase());
  }
}
console.log([...names].sort().join('\n'));
