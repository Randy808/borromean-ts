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
const gdbBytes = `{0x6f, 0x5c, 0x45, 0xad, 0xbc, 0x84, 0xc3, 0xdf, 0x2, 0xf1, 0xca, 0x25, 0x23, 0xcb, 0xb3, 0xb4, 0x91, 0x4e, 
  0xd5, 0x3, 0x97, 0x91, 0xff, 0x43, 0x1c, 0x98, 0xd4, 0xeb, 0xe4, 0xa6, 0xe8, 0xc7}`;

console.log(gdbBytesToHex(gdbBytes));
// Output: 0324a51e587be99af90b3cb78acac622e5c1c61d9de584dd866f27ab186879b017