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
  byId('downloads').replaceChildren(); byId('embed-result').textContent = '';
});
function attachCapacityIndicator(formId, outputId) {
const form = byId(formId);
const output = byId(outputId);
const coverOutput = byId('cover-capacity-result');
let capacityTimer;
let capacityRevision = 0;
async function updateCapacity(revision) {
  output.style.color = '';
  if (!form.elements.audio.files.length || !form.elements.bits.checkValidity() || !form.elements.start.checkValidity()) {
    coverOutput.textContent = 'Upload a WAV and select valid settings to see its capacity.';
    output.textContent = 'Choose a WAV file and valid settings to compare capacity.';
    return;
  }
  output.textContent = 'Checking payload size…';
  try {
    const result = await post('capacity', form);
    if (revision !== capacityRevision) return;
    coverOutput.textContent = `Capacity: ${result.capacity_bits.toLocaleString()} bits`;
    if (!form.elements.message.value) {
      output.textContent = 'Enter a message to see its payload size.';
      return;
    }
    const messageLength = Array.from(form.elements.message.value.trim()).length;
    const sizeLabel = messageLength >= 500 ? 'Large' : messageLength > 150 ? 'Medium' : 'Small';
    output.textContent = `Payload: ${result.required_bits.toLocaleString()} bits — ${sizeLabel}${result.fits ? ' (fits)' : ' (exceeds cover capacity)'}.`;
    output.style.color = result.fits ? '#216e39' : '#a12626';
  } catch (error) {
    if (revision !== capacityRevision) return;
    coverOutput.textContent = 'Cover capacity unavailable.';
    output.textContent = error.message;
    output.style.color = '#a12626';
  }
}
form.addEventListener('input', event => {
  clearTimeout(capacityTimer);
  const revision = ++capacityRevision;
  output.style.color = '';
  if (event.target.name !== 'message') coverOutput.textContent = 'Checking cover capacity…';
  output.textContent = 'Waiting to check payload size…';
  capacityTimer = setTimeout(() => updateCapacity(revision), 400);
});
}
attachCapacityIndicator('embed', 'embed-capacity-result');
byId('embed').onsubmit = event => {
  event.preventDefault();
  perform(event.submitter, async () => {
    const result = await post('embed', event.target);
    const blob = new Blob([Uint8Array.from(atob(result.audio), c => c.charCodeAt(0))], {type: 'audio/wav'});
    byId('downloads').replaceChildren();
    byId('stego').src = download(byId('downloads'), 'stego.wav', blob);
    download(byId('downloads'), 'public-key.pem', new Blob([result.public_key], {type: 'text/plain'}));
    byId('embed-result').textContent = `Embedded ${result.required_bytes} bytes / ${result.capacity_bytes} bytes available.`;
    byId('extract').elements.bits.value = event.target.elements.bits.value;
    byId('extract').elements.start.value = event.target.elements.start.value;
  });
};
function clearVerification() {
  byId('verdict').replaceChildren();
  byId('verdict').hidden = true;
}
function showVerification(result, filename, keyName) {
  const container = byId('verdict');
  container.replaceChildren();
  const heading = document.createElement('h3');
  heading.textContent = 'Verification Result';
  container.append(heading);
  const field = (label, value) => {
    const paragraph = document.createElement('p');
    const title = document.createElement('strong');
    title.textContent = `${label}: `;
    paragraph.append(title, document.createTextNode(value));
    container.append(paragraph);
  };
  field('File checked', filename);
  field('Verdict', result.verdict);
  field('Key used', keyName || "This server's own public key (same-machine test)");
  if (result.payload) {
    const subheading = document.createElement('h4');
    subheading.textContent = 'Extracted Payload';
    container.append(subheading);
    if (result.payload.metadata?.message) field('Message', result.payload.metadata.message);
    const payload = document.createElement('pre');
    payload.textContent = JSON.stringify(result.payload, null, 2);
    container.append(payload);
  }
  const rawHeading = document.createElement('h4');
  rawHeading.textContent = 'Full Verification Output';
  const rawOutput = document.createElement('pre');
  rawOutput.textContent = JSON.stringify(result, null, 2);
  container.append(rawHeading, rawOutput);
  container.hidden = false;
}
byId('clear-public-key').onclick = () => {
  byId('extract').elements.public_key.value = '';
  clearVerification();
  byId('error').textContent = '';
};
byId('extract').onsubmit = event => {
  event.preventDefault(); clearVerification();
  const filename = event.target.elements.audio.files[0]?.name || '';
  const keyName = event.target.elements.public_key.files[0]?.name;
  perform(event.submitter, async () => {
    const result = await post('extract', event.target);
    showVerification(result, filename, keyName);
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
