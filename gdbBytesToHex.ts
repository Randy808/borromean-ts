function gdbBytesToHex(gdbOutput: string): string {
  // Extract hex values from the format {0x..., 0x..., ...}
  const hexMatches = gdbOutput.match(/0x[0-9a-fA-F]+/g);
  
  if (!hexMatches) {
    throw new Error('No hex values found in GDB output');
  }
  
  // Remove 0x prefix and pad each byte to 2 digits
  return hexMatches
    .map(hex => hex.slice(2).padStart(2, '0'))
    .join('');
}

// Usage:
const gdbBytes = `{0x3, 0x24, 0xa5, 0x1e, 0x58, 0x7b, 0xe9, 0x9a, 0xf9, 0xb, 0x3c, 0xb7, 
  0x8a, 0xca, 0xc6, 0x22, 0xe5, 0xc1, 0xc6, 0x1d, 0x9d, 0xe5, 0x84, 0xdd, 
  0x86, 0x6f, 0x27, 0xab, 0x18, 0x68, 0x79, 0xb0, 0x17}`;

console.log(gdbBytesToHex(gdbBytes));
// Output: 0324a51e587be99af90b3cb78acac622e5c1c61d9de584dd866f27ab186879b017