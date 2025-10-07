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
const gdbMemDump = `0xffff5000a610: 0x00    0x14    0x66    0xf0    0x5b    0xc5    0x59    0xd7
0xffff5000a618: 0xe0    0xd8    0x47    0x1c    0x70    0x30    0x89    0xd7
0xffff5000a620: 0x9e    0x58    0x2f    0xdd    0x73    0x1b`;

console.log(gdbMemoryDumpToHex(gdbMemDump));
// Output: 3e4597483e22c59d44769c51affd945a952ab97fab4eb8f4b9cb8a2a424243e7