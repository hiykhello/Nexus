import { defineConfig, type Plugin } from 'vite';

function minifyLitTemplates(): Plugin {
  const collapse = (src: string, start: number, stopAtBrace: boolean): [string, number] => {
    let out = '';
    let i = start;
    const n = src.length;
    let braceDepth = 0;

    while (i < n) {
      const ch = src[i];
      if (stopAtBrace) {
        if (ch === '{') {
          braceDepth++;
          out += ch;
          i++;
          continue;
        }
        if (ch === '}') {
          if (braceDepth === 0) return [out, i];
          braceDepth--;
          out += ch;
          i++;
          continue;
        }
      }
      if (ch === '/' && src[i + 1] === '/') {
        const end = src.indexOf('\n', i + 2);
        const to = end === -1 ? n : end + 1;
        out += src.slice(i, to);
        i = to;
        continue;
      }
      if (ch === '/' && src[i + 1] === '*') {
        const end = src.indexOf('*/', i + 2);
        const to = end === -1 ? n : end + 2;
        out += src.slice(i, to);
        i = to;
        continue;
      }
      if (ch === "'" || ch === '"') {
        const q = ch;
        out += ch;
        i++;
        while (i < n) {
          if (src[i] === '\\' && i + 1 < n) {
            out += src.slice(i, i + 2);
            i += 2;
            continue;
          }
          out += src[i];
          if (src[i++] === q) break;
        }
        continue;
      }
      const isCss = src.startsWith('css`', i) && (i === 0 || !/[$\w]/.test(src[i - 1]));
      const isHtml = src.startsWith('html`', i) && (i === 0 || !/[$\w]/.test(src[i - 1]));
      const isPlainTpl = ch === '`';
      if (!isCss && !isHtml && !isPlainTpl) {
        out += src[i++];
        continue;
      }
      const tagLen = isCss ? 4 : isHtml ? 5 : 1;
      out += src.slice(i, i + tagLen);
      i += tagLen;
      let chunk = '';
      const flush = () => {
        if (!chunk) return;
        let c = chunk;
        if (isCss || isHtml) c = c.replace(/\r?\n[ \t]+/g, ' ');
        if (isCss) c = c.replace(/\s*([{};,])\s*/g, '$1');
        out += c;
        chunk = '';
      };
      while (i < n) {
        if (src[i] === '\\' && i + 1 < n) {
          chunk += src.slice(i, i + 2);
          i += 2;
          continue;
        }
        if (src[i] === '`') {
          flush();
          out += '`';
          i++;
          break;
        }
        if (src[i] === '$' && src[i + 1] === '{') {
          flush();
          out += '${';
          const [inner, endIdx] = collapse(src, i + 2, true);
          out += inner + '}';
          i = endIdx + 1;
          continue;
        }
        chunk += src[i++];
      }
    }
    return [out, i];
  };

  return {
    name: 'minify-lit-templates',
    enforce: 'pre',
    transform(code, id) {
      if (!id.endsWith('.ts') || id.includes('node_modules')) return null;
      if (!code.includes('html`') && !code.includes('css`')) return null;
      return { code: collapse(code, 0, false)[0], map: null };
    },
  };
}

export default defineConfig({
  base: '/',
  plugins: [minifyLitTemplates()],
  server: {
    port: 5173,
    proxy: {
      '/v1': {
        target: 'http://127.0.0.1:9090',
        ws: true,
      },
      '/metrics': 'http://127.0.0.1:9090',
      '/ssmapi': 'http://127.0.0.1:9090',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
  },
});
