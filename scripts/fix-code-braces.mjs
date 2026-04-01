/**
 * Escapes special characters inside <code> and <pre><code> blocks in .astro files.
 * Astro parses curly braces as JSX expressions in template HTML, and < as tag openers.
 * Problematic patterns in code blocks:
 *   {  }         → &#123; &#125;
 *   <<           → &lt;&lt;  (heredoc, bitshift)
 *   <%  %>       → &lt;%  %&gt;  (ASP/ERB templates)
 *   <?  ?>       → &lt;?  ?&gt;  (PHP, XML processing instructions)
 *   &#123;'&#123;'&#125;  → &#123;  (fix mangled JSX brace workarounds)
 *   &#123;'&#125;'&#125;  → &#125;
 *
 * Run: node scripts/fix-code-braces.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { globSync } from 'node:fs';

// Node 22+ has globSync; fall back to manual find if needed
let files;
try {
  files = globSync('src/pages/**/*.astro', { cwd: process.cwd() });
} catch {
  // Fallback for older Node
  const { execSync } = await import('node:child_process');
  files = execSync('find src/pages -name "*.astro"').toString().trim().split('\n').filter(Boolean);
}

let totalFixed = 0;

for (const file of files) {
  const filePath = join(process.cwd(), file);
  const original = readFileSync(filePath, 'utf8');

  // Fix { and } inside <code>...</code> blocks only.
  // Skip code blocks that already use set:html= (they don't need escaping).
  let fixed = original.replace(
    /<code([^>]*)>([\s\S]*?)<\/code>/g,
    (match, attrs, inner) => {
      // Don't touch blocks that use set:html — content is already a JS expression
      if (attrs.includes('set:html')) return match;

      let escaped = inner;

      // 1. Fix mangled JSX brace workarounds (from previous partial fix runs):
      //    &#123;'&#123;'&#125; → &#123;   (was {'{'} in JSX)
      //    &#123;'&#125;'&#125; → &#125;   (was {'}'} in JSX)
      escaped = escaped.replace(/&#123;'&#123;'&#125;/g, '&#123;');
      escaped = escaped.replace(/&#123;'&#125;'&#125;/g, '&#125;');

      // 2. Escape raw curly braces (JSX expression delimiters)
      escaped = escaped.replace(/\{/g, '&#123;');
      escaped = escaped.replace(/\}/g, '&#125;');

      // 3. Escape << (heredoc syntax, bitshift) — Astro misparses as fragment
      escaped = escaped.replace(/<<(?!-)/g, '&lt;&lt;');

      // 4. Escape <% %> (ASP/ERB template tags)
      escaped = escaped.replace(/<%/g, '&lt;%');
      escaped = escaped.replace(/%>/g, '%&gt;');

      // 5. Escape <? ?> (PHP tags, XML processing instructions)
      escaped = escaped.replace(/<\?/g, '&lt;?');
      escaped = escaped.replace(/\?>/g, '?&gt;');

      // 6. Escape remaining < followed by a letter, /, or ! (HTML/XML tags)
      //    This handles <script>, <svg>, <img>, </script>, <!-- etc. in code examples
      //    Must run after steps 3-5 to avoid double-escaping &lt; already written
      escaped = escaped.replace(/<(?=[a-zA-Z\/!])/g, '&lt;');

      return `<code${attrs}>${escaped}</code>`;
    }
  );

  if (fixed !== original) {
    writeFileSync(filePath, fixed, 'utf8');
    console.log(`Fixed: ${file}`);
    totalFixed++;
  }
}

console.log(`\nDone. Fixed ${totalFixed} files.`);
