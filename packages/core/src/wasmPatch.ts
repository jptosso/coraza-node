// Patch a WASM binary's memory section `min` value before instantiation.
//
// TinyGo emits a binary with a tiny initial memory (2 pages). CRS's regex
// compilation allocates heavily enough to hit linear-memory OOB before the
// WASI allocator can `memory.grow`. Bumping `min` to ~137 MiB fixes this,
// matching what `coraza-proxy-wasm` does post-build.
//
// Parsing is minimal — we walk the section list looking for section id=5
// (memory), decode its single entry's limits, and rewrite `min` in place.

const SECTION_MEMORY = 5

/**
 * Return the memory section's `min` (in 64 KiB pages), or `null` if the
 * module has no memory section. Used as a cheap check before deciding
 * whether to patch — when the binary was built with
 * `-extldflags --initial-memory=...` the value is already large enough
 * and we can skip the rewrite entirely.
 */
export function readInitialMemoryPages(wasm: Uint8Array): number | null {
  if (wasm.length < 8 || wasm[0] !== 0x00 || wasm[1] !== 0x61 || wasm[2] !== 0x73 || wasm[3] !== 0x6d) {
    return null
  }
  let i = 8
  while (i < wasm.length) {
    const sectionId = wasm[i]!
    i += 1
    const [size, after] = readULEB(wasm, i)
    i = after
    const sectionEnd = i + size
    if (sectionId === SECTION_MEMORY) {
      const [count, afterCount] = readULEB(wasm, i)
      if (count !== 1) return null
      // limits: flags (1), then min (ULEB)
      const [min] = readULEB(wasm, afterCount + 1)
      return min
    }
    i = sectionEnd
  }
  return null
}

/**
 * Rewrite the memory section's `min` to `pages` if smaller. Returns the
 * patched bytes. Leaves non-memory sections untouched and does not
 * validate anything beyond what's needed to locate/rewrite memory.min.
 */
export function patchInitialMemory(
  wasm: Uint8Array,
  pages: number,
): Uint8Array {
  // Magic + version
  if (wasm.length < 8 || wasm[0] !== 0x00 || wasm[1] !== 0x61 || wasm[2] !== 0x73 || wasm[3] !== 0x6d) {
    throw new Error('patchInitialMemory: not a WASM binary')
  }

  let i = 8
  while (i < wasm.length) {
    const sectionId = wasm[i]!
    i += 1
    const [size, after] = readULEB(wasm, i)
    i = after
    const sectionEnd = i + size

    if (sectionId === SECTION_MEMORY) {
      return patchMemorySection(wasm, i, sectionEnd, pages)
    }
    i = sectionEnd
  }
  // No memory section → nothing to patch (unusual; leave as-is).
  return wasm
}

function patchMemorySection(
  wasm: Uint8Array,
  start: number,
  end: number,
  pages: number,
): Uint8Array {
  let p = start
  const [count, afterCount] = readULEB(wasm, p)
  if (count !== 1) return wasm // not a module we know how to patch
  p = afterCount

  // limits: flags (1 byte), then min (ULEB), then optional max (ULEB).
  const flags = wasm[p]!
  p += 1

  const [currentMin, afterMin] = readULEB(wasm, p)
  if (currentMin >= pages) return wasm // already big enough

  // Rebuild the memory section with the new min; keep flags/max intact.
  const newMinBytes = writeULEB(pages)
  const oldMinBytes = afterMin - p
  const maxBytes = (flags & 0x01) ? end - afterMin : 0
  const newContent = new Uint8Array(
    // count (1) + flags (1) + newMin + max
    1 + 1 + newMinBytes.length + maxBytes,
  )
  let w = 0
  newContent[w++] = 0x01 // count
  newContent[w++] = flags
  newContent.set(newMinBytes, w)
  w += newMinBytes.length
  if (maxBytes > 0) {
    newContent.set(wasm.subarray(afterMin, end), w)
  }

  // Splice the new section in place of the old one, including a fresh
  // ULEB-encoded section size.
  const sizeBytes = writeULEB(newContent.length)

  // Original: [id:1][origSize:N][origContent:size] spanning (start-1..end)
  // where (start-1) is the section id byte and N bytes of ULEB size live
  // between id and content. Compute where the section starts including id:
  const sectionIdIdx = findSectionIdIndex(wasm, start, SECTION_MEMORY)
  if (sectionIdIdx < 0) return wasm

  const before = wasm.subarray(0, sectionIdIdx + 1) // include id byte
  const after = wasm.subarray(end)

  const out = new Uint8Array(before.length + sizeBytes.length + newContent.length + after.length)
  let o = 0
  out.set(before, o); o += before.length
  out.set(sizeBytes, o); o += sizeBytes.length
  out.set(newContent, o); o += newContent.length
  out.set(after, o)
  return out
}

function findSectionIdIndex(wasm: Uint8Array, contentStart: number, id: number): number {
  // Walk backwards from contentStart: preceding bytes are the ULEB size, and
  // before those is the 1-byte section id. We identify the id by scanning
  // forward from offset 8 until we hit a section whose content range
  // encloses contentStart.
  let i = 8
  while (i < wasm.length) {
    const sid = wasm[i]!
    const idByte = i
    i += 1
    const [size, after] = readULEB(wasm, i)
    i = after
    if (sid === id && i === contentStart) return idByte
    i += size
  }
  return -1
}

function readULEB(buf: Uint8Array, offset: number): [number, number] {
  let result = 0
  let shift = 0
  let i = offset
  for (;;) {
    const b = buf[i]!
    i += 1
    result |= (b & 0x7f) << shift
    if ((b & 0x80) === 0) break
    shift += 7
    if (shift > 35) throw new Error('ULEB too large')
  }
  return [result >>> 0, i]
}

function writeULEB(value: number): Uint8Array {
  const out: number[] = []
  let v = value >>> 0
  do {
    let byte = v & 0x7f
    v >>>= 7
    if (v !== 0) byte |= 0x80
    out.push(byte)
  } while (v !== 0)
  return new Uint8Array(out)
}
