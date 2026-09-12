const port = Number(process.argv[2] || 9333);
const tabs = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const tab = tabs.find(t => String(t.url || '').startsWith('https://security.oppo.com/cn/add'));
if (!tab) throw new Error('OPPO submission tab not found');

const ws = new WebSocket(tab.webSocketDebuggerUrl);
await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });

const expression = `(() => {
  const visible = el => !!el && getComputedStyle(el).display !== 'none' && getComputedStyle(el).visibility !== 'hidden' && el.getClientRects().length > 0;
  const textInputs = [...document.querySelectorAll('input[type="text"]')];
  const selects = [...document.querySelectorAll('.w-full.select.relative')].map(el => {
    const value = el.querySelector(':scope > .w-full.font-m.copy-size-14');
    return (value?.innerText || value?.textContent || '').trim();
  });
  const editor = document.querySelector('[contenteditable="true"][role="textarea"]');
  const file = document.querySelector('input[type="file"]')?.files?.[0] || null;
  const errors = [...document.querySelectorAll('.msg.copy-size-12')].filter(visible).map(el => (el.innerText || el.textContent || '').trim()).filter(Boolean);
  return {
    url: location.href,
    title: textInputs[0]?.value || '',
    severity: selects[0] || '',
    primary_type: selects[1] || '',
    subtype: selects[2] || '',
    domain: textInputs[1]?.value || '',
    editor_text: editor?.innerText || editor?.textContent || '',
    validation_errors: errors,
    attachment_name: file?.name || '',
    attachment_size: file?.size || 0,
    agreement_selected: !!document.querySelector('.checkbox.selected')
  };
})()`;

const result = await new Promise((resolve, reject) => {
  ws.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.id === 1) resolve(message.result?.result?.value);
  };
  ws.onerror = reject;
  ws.send(JSON.stringify({id: 1, method: 'Runtime.evaluate', params: {expression, returnByValue: true}}));
});
ws.close();
console.log(JSON.stringify(result, null, 2));
