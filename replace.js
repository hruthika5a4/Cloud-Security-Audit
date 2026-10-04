import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function walk(dir) {
  for (const f of fs.readdirSync(dir)) {
    const full = path.join(dir, f);
    if (fs.statSync(full).isDirectory()) walk(full);
    else if (full.endsWith('.js') || full.endsWith('.jsx')) {
      let content = fs.readFileSync(full, 'utf8');
      const origin = content;
      content = content.replace(/http:\/\/localhost:5000/g, 'https://security-audit-accelerator-backend-196053730058.asia-south1.run.app');
      if (content !== origin) {
        fs.writeFileSync(full, content);
        console.log('Fixed', full);
      }
    }
  }
}
walk(path.join(__dirname, 'src'));
