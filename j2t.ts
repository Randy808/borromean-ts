function gdbJacobianToTypeScript(gdbOutput: string): string {
  // Extract numbers from the format {x = {n = {...}}, y = {n = {...}}, z = {n = {...}}}
  const xMatch = gdbOutput.match(/x = \{n = \{([^}]+)\}\}/);
  const yMatch = gdbOutput.match(/y = \{n = \{([^}]+)\}\}/);
  const zMatch = gdbOutput.match(/z = \{n = \{([^}]+)\}\}/);
  
  if (!xMatch || !yMatch || !zMatch) {
    throw new Error('Failed to parse GDB output');
  }
  
  const parseNumbers = (str: string): string => {
    return str
      .split(',')
      .map(s => s.trim() + 'n')
      .join(', ');
  };
  
  const xNums = parseNumbers(xMatch[1]);
  const yNums = parseNumbers(yMatch[1]);
  const zNums = parseNumbers(zMatch[1]);
  
  return `jacobianArrToProjectivePoint(
  [${xNums}],
  [${yNums}],
  [${zNums}]
)`;
}

function xY(gdbOutput: string): string {
  // Extract numbers from the format {x = {n = {...}}, y = {n = {...}}, z = {n = {...}}}
  const xMatch = gdbOutput.match(/x = \{n = \{([^}]+)\}\}/);
  const yMatch = gdbOutput.match(/y = \{n = \{([^}]+)\}\}/);
  
  if (!xMatch || !yMatch) {
    throw new Error('Failed to parse GDB output');
  }
  
  const parseNumbers = (str: string): string => {
    return str
      .split(',')
      .map(s => s.trim() + 'n')
      .join(', ');
  };
  
  const xNums = parseNumbers(xMatch[1]);
  const yNums = parseNumbers(yMatch[1]);
  
  return `jacobianArrToProjectivePoint(
  [${xNums}],
  [${yNums}],
)`;
}

// Usage:
const gdbOutput = `{x = {n = {2237712096142064, 6118543680428061, 5661755893269285, 
      5093000537889386, 185517524850791}}, y = {n = {20319635515123069, 
      19669292734376138, 19017741244279886, 18639694936018407, 
      1127062039601232}}, z = {n = {3578244923336438, 1150374887650552, 
      4227050510168899, 1537668810532209, 166168209568631}}, infinity = 0}`;

console.log(gdbJacobianToTypeScript(gdbOutput));


let xyM = `{x = {n = {14493328530442, 3798737458865307, 2485056678854474, 
      3359337944824989, 106523285574344}}, y = {n = {2961459019530422, 
      1277607914326066, 2455117097591148, 473051163415351, 43552662608318}}, 
  infinity = 0}`;
  console.log(xY(xyM))