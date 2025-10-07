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
const gdbMemDump = `0xffff6374bd08: 0xc4    0x2c    0x27    0x25    0xc7    0xb9    0xd3    0x18
0xffff6374bd10: 0x4c    0xaf    0xc6    0xda    0x71    0x9b    0xae    0x48
0xffff6374bd18: 0x34    0xed    0x28    0xed    0xe8    0x4f    0x1a    0xa6
0xffff6374bd20: 0xd6    0x19    0xff    0x36    0x05    0xbb    0xd6    0x0f`;

console.log(gdbMemoryDumpToHex(gdbMemDump));
// Output: 3e4597483e22c59d44769c51affd945a952ab97fab4eb8f4b9cb8a2a424243e7