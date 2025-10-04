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
const gdbMemDump = `0xffff99f1bd08: 0x38    0x0e    0x60    0x35    0xb3    0xdd    0x4a    0x88
0xffff99f1bd10: 0x99    0x75    0xb3    0xb0    0xc1    0x88    0x79    0x99
0xffff99f1bd18: 0x0c    0x62    0xbc    0xba    0xe7    0x43    0xa9    0x50
0xffff99f1bd20: 0xab    0x7d    0x80    0xb9    0xb2    0xd9    0x01    0x73`;

console.log(gdbMemoryDumpToHex(gdbMemDump));
// Output: 3e4597483e22c59d44769c51affd945a952ab97fab4eb8f4b9cb8a2a424243e7