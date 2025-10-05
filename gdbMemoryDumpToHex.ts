function gdbMemoryDumpToHex(gdbOutput: string): string {
  // Extract all hex values
  const hexMatches = gdbOutput.match(/0x[0-9a-fA-F]+/g);
  
  if (!hexMatches) {
    throw new Error('No hex values found in GDB memory dump');
  }
  
  // Filter out addresses (they're longer, typically 12+ hex digits)
  // Byte values are always 1-2 hex digits after 0x
  return hexMatches
    .filter(hex => hex.length <= 4) // 0x + max 2 hex digits for bytes
    .map(hex => hex.slice(2).padStart(2, '0'))
    .join('');
}

// Usage:
const gdbMemDump = `0xffff8ef3bd08: 0xb4    0x8b    0x73    0x81    0x46    0x48    0xaa    0xdb
0xffff8ef3bd10: 0x73    0xa5    0xd9    0x09    0x37    0xba    0x38    0xea
0xffff8ef3bd18: 0x40    0x8c    0xcc    0x1e    0x6f    0xc2    0x20    0xc3
0xffff8ef3bd20: 0xa8    0x89    0x9d    0xf8    0xeb    0x6d    0xa5    0x63`;

console.log(gdbMemoryDumpToHex(gdbMemDump));
// Output: 3e4597483e22c59d44769c51affd945a952ab97fab4eb8f4b9cb8a2a424243e7