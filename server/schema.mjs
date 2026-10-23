const sections = ['home', 'about', 'work', 'skills', 'contact'];
const assets = ['mascot', 'brand', 'ip', 'editorial'];
export class SiteError extends Error { constructor(message, status = 400) { super(message); this.status = status; } }
function check(ok, message = '内容格式不正确') { if (!ok) throw new SiteError(message); }
function text(v, max = 10000) { check(typeof v === 'string' && v.length <= max); return v; }
function list(v, max) { check(Array.isArray(v) && v.length <= max); return v; }
function unique(items, key) { check(new Set(items.map(v => v[key])).size === items.length, `${key} 不可重复`); }
export function validateSite(input, mediaExists = () => true) {
  check(input && input.version === 1 && input.settings);
  function media(v) {
    check(v && typeof v === 'object');
    const src = text(v.src || '', 20 * 1024 * 1024), asset = text(v.asset || '', 50);
    check(!asset || assets.includes(asset), '未知内置素材');
    check(!src || /^data:(?:image\/(?:png|jpeg|webp|gif|avif)|video\/(?:mp4|webm));base64,[A-Za-z0-9+/=\r\n]+$/.test(src) || /^\/media\/[0-9a-f-]{36}\.(?:png|jpg|webp|gif|avif|mp4|webm)$/.test(src), '媒体地址不合法');
    if (src.startsWith('/media/')) check(mediaExists(src), '媒体文件不存在，请重新上传');
    const kind = v.kind === 'video' || /^data:video\//.test(src) || /\.(mp4|webm)$/.test(src) ? 'video' : 'image';
    return { id: text(v.id || 'media', 150), src, asset, alt: text(v.alt || ''), kind, type: text(v.type || '', 100) };
  }
  const s = input.settings, settings = {};
  for (const [key, min, max] of [['pageWidth', 960, 1600], ['spacing', 40, 160], ['heroSize', 64, 180], ['radius', 0, 48]]) { check(Number.isFinite(s[key]) && s[key] >= min && s[key] <= max); settings[key] = s[key]; }
  for (const [key, allowed] of [['columns', [1, 2, 3]], ['ratio', [1, 1.25, 1.5, 1.7778]], ['heroRatio', [1, 2.65, 1.7778, 1.5]], ['fit', ['contain', 'cover']]]) { check(allowed.includes(s[key])); settings[key] = s[key]; }
  for (const key of ['paper', 'ink', 'primary', 'primaryInk', 'secondary']) { check(/^#[0-9a-f]{6}$/i.test(s[key])); settings[key] = s[key]; } settings.motion = s.motion !== false;
  const order = list(input.sections, 5).map(v => { check(v && sections.includes(v.id) && typeof v.visible === 'boolean'); return { id: v.id, visible: v.visible }; }); unique(order, 'id'); check(order.length === 5);
  const texts = {}; check(input.texts && !Array.isArray(input.texts) && typeof input.texts === 'object'); check(Object.keys(input.texts).length <= 500);
  for (const [key, value] of Object.entries(input.texts)) { check(/^[a-z0-9-]{1,100}$/i.test(key)); texts[key] = text(value); }
  const projects = list(input.projects, 100).map(p => ({ id: text(p.id, 150), title: text(p.title), category: text(p.category), year: text(p.year), role: text(p.role), description: text(p.description), images: list(p.images, 100).map(media) })); unique(projects, 'id');
  const skills = list(input.skills, 100).map(s => ({ id: text(s.id, 150), title: text(s.title), description: text(s.description) })); unique(skills, 'id');
  const blocks = list(input.blocks, 100).map(b => { check(sections.includes(b.section) && ['title', 'body', 'caption'].includes(b.style)); return { id: text(b.id, 150), section: b.section, style: b.style, text: text(b.text) }; }); unique(blocks, 'id');
  const pages = list(input.pages || [], 50).map(p => {
    check(/^[a-z0-9][a-z0-9-]{0,59}$/.test(p.slug) && !['api', 'media', 'admin', 'login', 'home'].includes(p.slug), '子页面网址只可包含小写字母、数字和短横线');
    check(typeof p.visible === 'boolean' && ['single', 'grid', 'split'].includes(p.layout));
    const blocks = list(p.blocks, 100).map(b => { check(['text', 'media'].includes(b.kind)); return b.kind === 'media' ? { id: text(b.id, 150), kind: 'media', media: media(b.media) } : { id: text(b.id, 150), kind: 'text', style: ['title', 'body', 'caption'].includes(b.style) ? b.style : 'body', text: text(b.text) }; }); unique(blocks, 'id');
    return { id: text(p.id, 150), slug: p.slug, title: text(p.title), description: text(p.description), visible: p.visible, layout: p.layout, blocks };
  }); unique(pages, 'id'); unique(pages, 'slug');
  return { version: 1, designRevision: 2, siteId: text(input.siteId || 'portfolio-studio-a82e1b', 150), updatedAt: Date.now(), texts, settings, sections: order, hero: media(input.hero), projects, skills, blocks, pages };
}
export function sniffMedia(buffer, declared) {
  let found;
  if (buffer.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) found = ['image/png', 'png'];
  else if (buffer[0] === 255 && buffer[1] === 216 && buffer[2] === 255) found = ['image/jpeg', 'jpg'];
  else if (/^GIF8[79]a$/.test(buffer.subarray(0, 6).toString('ascii'))) found = ['image/gif', 'gif'];
  else if (buffer.subarray(0, 4).toString() === 'RIFF' && buffer.subarray(8, 12).toString() === 'WEBP') found = ['image/webp', 'webp'];
  else if (buffer.subarray(4, 8).toString() === 'ftyp') { const brands = buffer.subarray(8, 64).toString('ascii'); if (/avif|avis/.test(brands)) found = ['image/avif', 'avif']; else if (/isom|iso[2-9]|mp4[12]|avc1|M4V /.test(brands)) found = ['video/mp4', 'mp4']; }
  else if (buffer.subarray(0, 4).equals(Buffer.from([26,69,223,163]))) found = ['video/webm', 'webm'];
  if (!found || declared !== found[0]) throw new SiteError('文件类型与内容不符，或文件格式不受支持', 415);
  return { type: found[0], extension: found[1], kind: found[0].startsWith('video/') ? 'video' : 'image' };
}
