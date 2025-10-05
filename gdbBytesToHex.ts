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
const gdbBytes = `{0xf3, 0x51, 0xcd, 0x85, 0x10, 0xca, 0x96, 0xeb, 0xd, 0x51, 0x69, 
  0x96, 0x31, 0xf9, 0x7, 0x1b, 0x81, 0xd0, 0xf2, 0xe, 0x97, 0xe4, 0xd4, 0xd, 
  0x7, 0x55, 0xc5, 0x11, 0xf4, 0xc8, 0xcf, 0xa2, 0xae}`;

console.log(gdbBytesToHex(gdbBytes));
// Output: 0324a51e587be99af90b3cb78acac622e5c1c61d9de584dd866f27ab186879b017