// Injected into every vendor page before their own scripts run.
// Records what YOU click and choose so the next run can replay it.
// Survives navigation via sessionStorage. Never records passwords.
(() => {
  const KEY = '__fsrec';
  // Armed by default, switched OFF by the driver while it is filling the form itself.
  // Without this the tool records its own autofill and "learns" what it already does.
  if (window.__fsrec_on === undefined) window.__fsrec_on = true;
  const live = () => window.__fsrec_on === true;
  const load = () => { try { return JSON.parse(sessionStorage.getItem(KEY) || '[]'); } catch (e) { return []; } };
  const push = s => { const a = load(); a.push(s); try { sessionStorage.setItem(KEY, JSON.stringify(a.slice(-80))); } catch (e) {} };

  const esc = s => (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/["\\]/g, '\\$&');
  const uniq = s => { try { return document.querySelectorAll(s).length === 1; } catch (e) { return false; } };

  function sel(el) {
    if (!el || el.nodeType !== 1) return null;
    if (el.id && uniq('#' + esc(el.id))) return '#' + esc(el.id);
    const tag = el.tagName.toLowerCase();
    if (el.name && uniq(`${tag}[name="${esc(el.name)}"]`)) return `${tag}[name="${esc(el.name)}"]`;
    for (const a of ['data-testid', 'data-test', 'aria-label']) {
      const v = el.getAttribute(a);
      if (v && uniq(`[${a}="${esc(v)}"]`)) return `[${a}="${esc(v)}"]`;
    }
    if (el.value && (el.type === 'radio' || el.type === 'checkbox')) {
      const s = `input[type="${el.type}"][value="${esc(el.value)}"]`;
      if (uniq(s)) return s;
    }
    const path = [];
    let node = el;
    while (node && node.nodeType === 1 && path.length < 7) {
      if (node.id) { path.unshift('#' + esc(node.id)); break; }
      let part = node.tagName.toLowerCase();
      const p = node.parentElement;
      if (p) {
        const same = [...p.children].filter(c => c.tagName === node.tagName);
        if (same.length > 1) part += `:nth-of-type(${same.indexOf(node) + 1})`;
      }
      path.unshift(part);
      node = p;
    }
    return path.join(' > ') || null;
  }

  const label = el => {
    let t = '';
    if (el.labels) for (const l of el.labels) t += ' ' + (l.innerText || '');
    return (t || el.getAttribute('aria-label') || el.innerText || el.value || '').trim().slice(0, 70);
  };
  const inCaptcha = el => !!(el.closest && el.closest('.g-recaptcha, .h-captcha, [data-sitekey], #recaptcha'));

  document.addEventListener('click', e => {
    if (!live()) return;
    const el = e.target.closest('button, input[type=submit], input[type=radio], input[type=checkbox], a, [role=button], [role=option], li, label');
    if (!el || inCaptcha(el)) return;
    const s = sel(el);
    if (!s) return;
    const type = (el.type || '').toLowerCase();
    push({ act: type === 'radio' || type === 'checkbox' ? 'check' : 'click',
           sel: s, text: label(el), tag: el.tagName.toLowerCase(), type });
  }, true);

  document.addEventListener('change', e => {
    if (!live()) return;
    const el = e.target;
    if (!el || !el.tagName || inCaptcha(el)) return;
    if (el.type === 'password') return;                       // never
    const s = sel(el);
    if (!s) return;
    if (el.tagName === 'SELECT') {
      const o = el.options[el.selectedIndex];
      push({ act: 'select', sel: s, value: el.value, text: (o ? o.text : '').trim().slice(0, 70) });
    } else if (el.type === 'radio' || el.type === 'checkbox') {
      push({ act: 'check', sel: s, checked: el.checked, text: label(el) });
    } else if (el.value) {
      push({ act: 'fill', sel: s, value: el.value, text: label(el) });
    }
  }, true);
})();
