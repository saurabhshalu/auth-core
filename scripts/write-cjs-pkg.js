// scripts/write-cjs-pkg.js
import { writeFileSync, mkdirSync } from 'node:fs';
const dir = './dist/cjs';
mkdirSync(dir, { recursive: true });
writeFileSync(`${dir}/package.json`, JSON.stringify({ type: 'commonjs' }, null, 2));
console.log('Wrote', `${dir}/package.json`);