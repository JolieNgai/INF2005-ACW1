const byId = id => document.getElementById(id);
const urls = new Map();
function urlFor(name, blob) {
  if (urls.has(name)) URL.revokeObjectURL(urls.get(name));
  const url = URL.createObjectURL(blob); urls.set(name, url); return url;
}
function download(container, name, blob) {
  const link = document.createElement('a');
  link.className = 'download-link';
  link.href = urlFor(name, blob); link.download = name; link.textContent = `Download ${name}`;
  container.append(link); return link.href;
}
async function post(action, form) {
  const response = await fetch(`/audio/${action}`, {method: 'POST', body: new FormData(form)});
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    throw new Error(result.error || `Request failed (${response.status})`);
  }
  return ['tamper', 'generate-cannot-verify-test', 'generate-wrong-public-key'].includes(action) ? response.blob() : response.json();
}
async function perform(button, task) {
  byId('error').textContent = ''; button.disabled = true;
  try { await task(); } catch (error) { byId('error').textContent = error.message; }
  finally { button.disabled = false; }
}
byId('embed').elements.audio.addEventListener('change', event => {
  const file = event.target.files[0];
  if (file) byId('cover').src = urlFor('cover', file);
  byId('stego').removeAttribute('src'); byId('stego').load();
  byId('downloads').replaceChildren(); byId('capacity-result').textContent = '';
});
byId('capacity').onclick = event => perform(event.target, async () => {
  const result = await post('capacity', byId('embed'));
  byId('capacity-result').textContent = `Packet capacity: ${result.capacity_bytes} bytes (includes signature and metadata). Exact required size is checked when embedding.`;
});
byId('embed').onsubmit = event => {
  event.preventDefault();
  perform(event.submitter, async () => {
    const result = await post('embed', event.target);
    const blob = new Blob([Uint8Array.from(atob(result.audio), c => c.charCodeAt(0))], {type: 'audio/wav'});
    byId('downloads').replaceChildren();
    byId('stego').src = download(byId('downloads'), 'stego.wav', blob);
    download(byId('downloads'), 'public-key.pem', new Blob([result.public_key], {type: 'text/plain'}));
    byId('capacity-result').textContent = `Embedded ${result.required_bytes} bytes / ${result.capacity_bytes} bytes available.`;
    byId('extract').elements.bits.value = event.target.elements.bits.value;
    byId('extract').elements.start.value = event.target.elements.start.value;
  });
};
byId('extract').onsubmit = event => {
  event.preventDefault(); byId('verdict').textContent = '';
  perform(event.submitter, async () => {
    const result = await post('extract', event.target);
    byId('verdict').textContent = JSON.stringify(result, null, 2);
  });
};
byId('tamper').onsubmit = event => {
  event.preventDefault();
  perform(event.submitter, async () => {
    const blob = await post('tamper', event.target);
    byId('tampered-download').replaceChildren();
    download(byId('tampered-download'), 'tampered.wav', blob);
  });
};
byId('cannot-verify-demo').onsubmit = event => {
  event.preventDefault();
  byId('corrupt-download').replaceChildren();
  perform(event.submitter, async () => {
    const blob = await post('generate-cannot-verify-test', event.target);
    download(byId('corrupt-download'), 'cannot_verify.wav', blob);
  });
};

byId('wrong-key-demo').onsubmit = event => {
  event.preventDefault();
  byId('wrong-key-download').replaceChildren();
  perform(event.submitter, async () => {
    const blob = await post('generate-wrong-public-key', event.target);
    download(byId('wrong-key-download'), 'wrong-public-key.pem', blob);
  });
};
