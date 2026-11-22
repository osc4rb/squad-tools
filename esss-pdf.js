/* esss-pdf.js: fills the CS-37 eSSS (AF IMT 1768, an Adobe XFA form) with no library.
 *
 * How: the form keeps its typed values in one XML stream (the XFA "datasets" packet). This code
 * finds that stream, writes the new values into it, and appends the new stream plus a small
 * cross-reference section to the END of the file (a PDF "incremental update"). The original bytes
 * are never changed, which is also how Acrobat itself saves a filled form, so the form's own
 * signature fields and Reader rights keep working.
 *
 * Works in the browser and in Node 18+ (both have DecompressionStream).
 */
(function (root) {
  'use strict';

  const latin1 = (u8, a = 0, b = u8.length) => {
    let s = '';
    for (let i = a; i < b; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, Math.min(b, i + 0x8000)));
    return s;
  };
  const enc = (s) => { const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i) & 255; return u; };
  const utf8 = (s) => new TextEncoder().encode(s);
  const fromUtf8 = (u8) => new TextDecoder('utf-8').decode(u8);

  /* ---- Standard security handler, AES-128 (V4/R4), blank open password: the eSSS ships this way.
     Its permission flags allow filling form fields, which is all this file does. ---- */
  function md5(bytes) {
    const K = new Int32Array(64), S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
    const n = bytes.length, total = ((n + 8) >>> 6) + 1, M = new Int32Array(total * 16);
    for (let i = 0; i < n; i++) M[i >> 2] |= bytes[i] << ((i % 4) * 8);
    M[n >> 2] |= 0x80 << ((n % 4) * 8);
    M[total * 16 - 2] = n * 8;
    let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
    for (let c = 0; c < total; c++) {
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        const tmp = D; D = C; C = B;
        const x = (A + F + K[i] + M[c * 16 + g]) | 0, s = S[(i >> 4) * 4 + (i % 4)];
        B = (B + ((x << s) | (x >>> (32 - s)))) | 0; A = tmp;
      }
      a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
    }
    const out = new Uint8Array(16);
    [a0, b0, c0, d0].forEach((v, i) => { for (let j = 0; j < 4; j++) out[i * 4 + j] = (v >>> (8 * j)) & 255; });
    return out;
  }
  const hexBytes = (h) => { const u = new Uint8Array(h.length / 2); for (let i = 0; i < u.length; i++) u[i] = parseInt(h.substr(i * 2, 2), 16); return u; };
  function pdfString(str) { /* literal "(...)" or hex "<...>" -> bytes */
    str = str.trim();
    if (str[0] === '<') return hexBytes(str.slice(1, -1).replace(/\s+/g, ''));
    const out = []; const s = str.slice(1, -1);
    for (let i = 0; i < s.length; i++) {
      let c = s[i];
      if (c !== '\\') { out.push(c.charCodeAt(0) & 255); continue; }
      c = s[++i];
      const map = { n: 10, r: 13, t: 9, b: 8, f: 12, '(': 40, ')': 41, '\\': 92 };
      if (c in map) out.push(map[c]);
      else if (/[0-7]/.test(c)) { let o = c; while (o.length < 3 && /[0-7]/.test(s[i + 1])) o += s[++i]; out.push(parseInt(o, 8) & 255); }
      else if (c === '\r') { if (s[i + 1] === '\n') i++; }
      else if (c !== '\n') out.push(c.charCodeAt(0) & 255);
    }
    return new Uint8Array(out);
  }
  /* read one PDF string value for key k out of a dict given as raw text */
  function dictString(text, k) {
    const i = text.search(new RegExp('/' + k + '\\s*[(<](?!<)'));
    if (i < 0) return null;
    let p = text.indexOf(k, i) + k.length; while (/\s/.test(text[p])) p++;
    if (text[p] === '<') return pdfString(text.slice(p, text.indexOf('>', p) + 1));
    let depth = 0, q = p;
    for (; q < text.length; q++) { if (text[q] === '\\') { q++; continue; } if (text[q] === '(') depth++; if (text[q] === ')' && --depth === 0) break; }
    return pdfString(text.slice(p, q + 1));
  }
  const PAD = hexBytes('28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A');
  function fileKey(encText, id0) {
    const O = dictString(encText, 'O'), P = +/\/P\s+(-?\d+)/.exec(encText)[1];
    const plainMeta = /\/EncryptMetadata\s+false/.test(encText);
    const parts = [PAD, O.subarray(0, 32), new Uint8Array([P & 255, (P >>> 8) & 255, (P >>> 16) & 255, (P >>> 24) & 255]), id0];
    if (plainMeta) parts.push(new Uint8Array([255, 255, 255, 255]));
    let h = md5(cat(parts));
    for (let i = 0; i < 50; i++) h = md5(h.subarray(0, 16));
    return h.subarray(0, 16);
  }
  function objKey(key, num, gen) {
    return md5(cat([key, new Uint8Array([num & 255, (num >> 8) & 255, (num >> 16) & 255, gen & 255, (gen >> 8) & 255]), enc('sAlT')]));
  }
  async function aes(key, op, iv, data) {
    const k = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, [op]);
    return new Uint8Array(await crypto.subtle[op]({ name: 'AES-CBC', iv }, k, data));
  }
  const decryptObj = async (sec, num, data) => sec ? aes(objKey(sec.key, num, 0), 'decrypt', data.subarray(0, 16), data.subarray(16)) : data;
  async function encryptObj(sec, num, data) {
    if (!sec) return data;
    const iv = crypto.getRandomValues(new Uint8Array(16));
    return cat([iv, await aes(objKey(sec.key, num, 0), 'encrypt', iv, data)]);
  }

  async function inflate(u8) {
    const ds = new DecompressionStream('deflate');
    const out = new Response(new Blob([u8]).stream().pipeThrough(ds));
    return new Uint8Array(await out.arrayBuffer());
  }

  /* raw stream bytes of the object whose "obj" keyword starts at `at` */
  function streamAt(u8, s, at) {
    const dictStart = s.indexOf('<<', at);
    const kw = s.indexOf('stream', dictStart);
    const dict = s.slice(dictStart, kw);
    let p = kw + 6;
    if (s[p] === '\r') p++;
    if (s[p] === '\n') p++;
    const len = /\/Length\s+(\d+)(?!\s+\d+\s+R)/.exec(dict);
    const end = len ? p + (+len[1]) : s.indexOf('endstream', p);
    return { dict, data: u8.subarray(p, end) };
  }

  /* Index every object: raw "N G obj" and objects packed in object streams. Later wins. */
  async function index(u8, sec) {
    const s = latin1(u8);
    const objs = new Map(); // num -> {pos, text} (text for objstm members, pos for raw)
    const re = /(?:^|[^0-9])(\d+)\s+(\d+)\s+obj\b/g;
    let m;
    const raw = [];
    while ((m = re.exec(s))) raw.push({ num: +m[1], pos: m.index + m[0].indexOf(m[1]), kw: m.index + m[0].length });
    for (const r of raw) {
      const head = s.slice(r.kw, r.kw + 200);
      objs.set(r.num, { order: r.pos, raw: r });
      if (/\/Type\s*\/ObjStm/.test(head) || /\/Type\s*\/ObjStm/.test(s.slice(r.kw, s.indexOf('stream', r.kw)))) {
        const { dict, data } = streamAt(u8, s, r.kw);
        const n = +(/\/N\s+(\d+)/.exec(dict) || [0, 0])[1];
        const first = +(/\/First\s+(\d+)/.exec(dict) || [0, 0])[1];
        const plain = await decryptObj(sec, r.num, data);
        const body = latin1(/FlateDecode/.test(dict) ? await inflate(plain) : plain);
        const nums = body.slice(0, first).trim().split(/\s+/).map(Number);
        for (let i = 0; i < n; i++) {
          const num = nums[2 * i], off = first + nums[2 * i + 1];
          const nextOff = i + 1 < n ? first + nums[2 * i + 3] : body.length;
          const prev = objs.get(num);
          if (!prev || prev.order < r.pos) objs.set(num, { order: r.pos + 1e-3 * (i + 1), text: body.slice(off, nextOff) });
        }
      }
    }
    return { s, objs };
  }

  function objText(ix, num) {
    const o = ix.objs.get(num);
    if (!o) throw new Error('object ' + num + ' not found');
    if (o.text != null) return o.text;
    const end = ix.s.indexOf('endobj', o.raw.kw);
    const body = ix.s.slice(o.raw.kw, end);
    const st = body.indexOf('stream');
    return st >= 0 ? body.slice(0, st) : body;
  }

  function lastTrailer(s) {
    const sx = s.lastIndexOf('startxref');
    const off = +/startxref\s+(\d+)/.exec(s.slice(sx))[1];
    let dict;
    if (s.startsWith('xref', off)) {
      const t = s.indexOf('trailer', off);
      dict = s.slice(t, s.indexOf('startxref', t));
    } else {
      const kw = s.indexOf('obj', off) + 3;
      dict = s.slice(kw, s.indexOf('stream', kw));
    }
    return { off, dict };
  }

  async function readForm(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (latin1(u8, 0, 5) !== '%PDF-') throw new Error('This is not a PDF file.');
    const s0 = latin1(u8);
    const tr = lastTrailer(s0);
    let sec = null;
    const encRef = /\/Encrypt\s+(\d+)\s+\d+\s+R/.exec(tr.dict);
    if (encRef) {
      const m = new RegExp('(?:^|[^0-9])' + encRef[1] + '\\s+0\\s+obj').exec(s0);
      if (!m) throw new Error('Cannot read this PDF’s security settings.');
      const encText = s0.slice(m.index, s0.indexOf('endobj', m.index));
      if (!/\/Filter\s*\/Standard/.test(encText) || !/\/R\s+4\b/.test(encText) || !/AESV2/.test(encText))
        throw new Error('This PDF uses a security setting this tool does not handle. Use the blank eSSS from your squadron.');
      const idm = /\/ID\s*\[\s*(<[0-9A-Fa-f\s]*>|\((?:\\.|[^\\)])*\))/.exec(tr.dict);
      if (!idm) throw new Error('This PDF has no file ID.');
      sec = { key: fileKey(encText, pdfString(idm[1])) };
    }
    const ix = await index(u8, sec);
    const rootNum = +(/\/Root\s+(\d+)\s+\d+\s+R/.exec(tr.dict) || [])[1];
    const cat = objText(ix, rootNum);
    const af = /\/AcroForm\s+(\d+)\s+\d+\s+R/.exec(cat);
    const afText = af ? objText(ix, +af[1]) : cat;
    const ds = /\(datasets\)\s*(\d+)\s+\d+\s+R/.exec(afText);
    if (!ds) throw new Error('No XFA form data found. Pick the blank eSSS (Staff Summary Sheet) PDF.');
    const dsNum = +ds[1];
    const o = ix.objs.get(dsNum);
    const { dict, data } = streamAt(u8, ix.s, o.raw.kw);
    let xml;
    try {
      const plain = await decryptObj(sec, dsNum, data);
      xml = fromUtf8(/FlateDecode/.test(dict) ? await inflate(plain) : plain);
    } catch (e) { throw new Error('Could not open the form data in this PDF.'); }
    if (!/<SUMMARY[\s>/]/.test(xml) || !/<TOONE[\s>/]/.test(xml)) throw new Error('This PDF is not the Staff Summary Sheet (AF IMT 1768).');
    return { u8, ix, tr, sec, dsNum, dsDict: dict, xml };
  }

  const xmlEsc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').replace(/\r\n?|\n/g, '&#xD;');

  /* values: { FIELDNAME: string } ; '' clears a field */
  function setFields(xml, values) {
    let out = xml;
    for (const [name, value] of Object.entries(values)) {
      const re = new RegExp('<' + name + '(\\s*)/>|<' + name + '(\\s*)>[\\s\\S]*?</' + name + '\\s*>');
      if (!re.test(out)) throw new Error('Field ' + name + ' is missing from this form.');
      const v = xmlEsc(value == null ? '' : value);
      out = out.replace(re, v === '' ? '<' + name + '\n/>' : '<' + name + '\n>' + v + '</' + name + '\n>');
    }
    return out;
  }

  function cat(parts) {
    let n = 0; for (const p of parts) n += p.length;
    const out = new Uint8Array(n); let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  /* Returns a new Uint8Array: the original file + one incremental update. */
  async function fill(bytes, values) {
    const f = await readForm(bytes);
    const newXml = await encryptObj(f.sec, f.dsNum, utf8(setFields(f.xml, values)));
    const u8 = f.u8;
    const size = +(/\/Size\s+(\d+)/.exec(f.tr.dict) || [])[1];
    const tail = latin1(u8, Math.max(0, u8.length - 2));
    const pre = enc(/[\r\n]$/.test(tail) ? '' : '\n');
    let off = u8.length + pre.length;

    const dsHead = enc(f.dsNum + ' 0 obj\n<</Type/EmbeddedFile/Length ' + newXml.length + '>>\nstream\n');
    const dsTail = enc('\nendstream\nendobj\n');
    const dsOff = off;
    off += dsHead.length + newXml.length + dsTail.length;

    const xrefNum = size, xrefOff = off;
    const row = (o) => [1, (o >>> 24) & 255, (o >>> 16) & 255, (o >>> 8) & 255, o & 255, 0, 0];
    const ent = new Uint8Array([...row(dsOff), ...row(xrefOff)]);
    const keep = ['Root', 'Encrypt', 'Info', 'ID'].map((k) => {
      const m = new RegExp('/' + k + '\\s*(\\d+\\s+\\d+\\s+R|\\[[^\\]]*\\])').exec(f.tr.dict);
      return m ? '/' + k + ' ' + m[1] : '';
    }).join('');
    const xHead = enc(xrefNum + ' 0 obj\n<</Type/XRef/Size ' + (size + 1) + '/Index[' + f.dsNum + ' 1 ' + xrefNum + ' 1]/W[1 4 2]' +
      keep + '/Prev ' + f.tr.off + '/Length ' + ent.length + '>>\nstream\n');
    const xTail = enc('\nendstream\nendobj\nstartxref\n' + xrefOff + '\n%%EOF\n');
    return cat([u8, pre, dsHead, newXml, dsTail, xHead, ent, xTail]);
  }

  async function readValues(bytes) {
    const f = await readForm(bytes);
    const out = {};
    const re = /<([A-Za-z_][\w]*)\s*>([^<]*)<\/\1\s*>/g;
    let m;
    const body = f.xml.slice(f.xml.indexOf('<xfa:data'));
    while ((m = re.exec(body))) out[m[1]] = m[2].replace(/&#xD;/g, '\n').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
    return out;
  }

  const api = { fill, readValues, readForm, setFields };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.EsssPdf = api;
})(typeof self !== 'undefined' ? self : this);
