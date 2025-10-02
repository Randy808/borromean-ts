export function secp256k1_scalar_add(
  a: Uint8Array, 
  b: Uint8Array
): { result: Uint8Array} {
  // Convert 32-byte buffers to 8 limbs of 32 bits each (little-endian)
  const aLimbs: bigint[] = new Array(8);
  const bLimbs: bigint[] = new Array(8);
  
  for (let i = 0; i < 8; i++) {
    const offset = i * 4;
    aLimbs[i] = 
      BigInt(a[offset]) | 
      (BigInt(a[offset + 1]) << 8n) | 
      (BigInt(a[offset + 2]) << 16n) | 
      (BigInt(a[offset + 3]) << 24n);
    
    bLimbs[i] = 
      BigInt(b[offset]) | 
      (BigInt(b[offset + 1]) << 8n) | 
      (BigInt(b[offset + 2]) << 16n) | 
      (BigInt(b[offset + 3]) << 24n);
  }
  
  // Perform addition with carry propagation
  const rLimbs: bigint[] = new Array(8);
  let t = 0n;
  
  t = aLimbs[0] + bLimbs[0];
  rLimbs[0] = t & 0xFFFFFFFFn;
  t >>= 32n;
  
  t += aLimbs[1] + bLimbs[1];
  rLimbs[1] = t & 0xFFFFFFFFn;
  t >>= 32n;
  
  t += aLimbs[2] + bLimbs[2];
  rLimbs[2] = t & 0xFFFFFFFFn;
  t >>= 32n;
  
  t += aLimbs[3] + bLimbs[3];
  rLimbs[3] = t & 0xFFFFFFFFn;
  t >>= 32n;
  
  t += aLimbs[4] + bLimbs[4];
  rLimbs[4] = t & 0xFFFFFFFFn;
  t >>= 32n;
  
  t += aLimbs[5] + bLimbs[5];
  rLimbs[5] = t & 0xFFFFFFFFn;
  t >>= 32n;
  
  t += aLimbs[6] + bLimbs[6];
  rLimbs[6] = t & 0xFFFFFFFFn;
  t >>= 32n;
  
  t += aLimbs[7] + bLimbs[7];
  rLimbs[7] = t & 0xFFFFFFFFn;
  t >>= 32n;
  
  
  // Convert result limbs back to 32-byte buffer (little-endian)
  const result = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const offset = i * 4;
    const limb = rLimbs[i];
    result[offset] = Number(limb & 0xFFn);
    result[offset + 1] = Number((limb >> 8n) & 0xFFn);
    result[offset + 2] = Number((limb >> 16n) & 0xFFn);
    result[offset + 3] = Number((limb >> 24n) & 0xFFn);
  }
  
  return { result };
}