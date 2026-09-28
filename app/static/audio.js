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
let capacityTimer;
let capacityRevision = 0;
byId('embed').addEventListener('input', () => {
  clearTimeout(capacityTimer);
  const revision = ++capacityRevision;
  const form = byId('embed');
  const cover = byId('cover-capacity-result');
  const output = byId('embed-capacity-result');
  output.style.color = '';
  if (!form.elements.audio.files.length) {
    cover.textContent = 'Upload a WAV to see its capacity in bits.';
    output.textContent = 'Enter a message to see its payload size.';
    return;
  }
  cover.textContent = 'Checking cover capacity…';
  output.textContent = 'Checking payload size…';
  capacityTimer = setTimeout(async () => {
    try {
      const result = await post('capacity', form);
      if (revision !== capacityRevision) return;
      cover.textContent = `Capacity: ${result.capacity_bits.toLocaleString()} bits`;
      if (!form.elements.message.value) {
        output.textContent = 'Enter a message to see its payload size.';
        return;
      }
      const length = Array.from(form.elements.message.value.trim()).length;
      const label = length >= 500 ? 'Large' : length > 150 ? 'Medium' : 'Small';
      output.textContent = `Payload: ${result.required_bits.toLocaleString()} bits — ${label} (${result.fits ? 'fits' : 'exceeds cover capacity'}).`;
      output.style.color = result.fits ? '#216e39' : '#a12626';
    } catch (error) {
      if (revision !== capacityRevision) return;
      cover.textContent = 'Cover capacity unavailable.';
      output.textContent = error.message;
      output.style.color = '#a12626';
    }
  }, 400);
});
byId('embed').onsubmit = event => {
  event.preventDefault();
  perform(event.submitter, async () => {
    const result = await post('embed', event.target);
    const blob = new Blob([Uint8Array.from(atob(result.audio), c => c.charCodeAt(0))], {type: 'audio/wav'});
    byId('downloads').replaceChildren();
    byId('stego').src = download(byId('downloads'), 'stego.wav', blob);
    download(byId('downloads'), 'public-key.pem', new Blob([result.public_key], {type: 'text/plain'}));
    byId('capacity-result').textContent = `Embedded ${result.required_bytes} bytes / ${result.capacity_bytes} bytes available. Derived start index: ${result.start_index}.`;
    byId('extract').elements.bits.value = event.target.elements.bits.value;
    byId('extract').elements.start.value = '';
  });
};
byId('extract').onsubmit = event => {
  event.preventDefault();
  byId('verification-result').hidden = true;
  byId('extracted-payload').hidden = true;
  byId('extracted-message-row').hidden = true;
  byId('extracted-message').textContent = '';
  byId('payload-details').textContent = '';
  const filename = event.target.elements.audio.files[0]?.name || '';
  const keyName = event.target.elements.public_key.files[0]?.name;
  perform(event.submitter, async () => {
    const result = await post('extract', event.target);
    byId('verified-filename').textContent = filename;
    byId('verdict').textContent = result.verdict;
    byId('verified-key').textContent = keyName || "This server's own public key (same-machine test)";
    byId('verification-output').textContent = JSON.stringify(result, null, 2);
    if (result.payload) {
      const message = result.payload.metadata?.message;
      if (typeof message === 'string' && message.length > 0) {
        byId('extracted-message').textContent = message;
        byId('extracted-message-row').hidden = false;
      }
      byId('payload-details').textContent = JSON.stringify(result.payload, null, 2);
      byId('extracted-payload').hidden = false;
    }
    byId('verification-result').hidden = false;
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
