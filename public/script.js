const $ = id => document.getElementById(id);
const input = $('inputText'), output = $('output'), algorithm = $('algorithm'), parameter = $('parameter'), parameterLabel = $('parameterLabel'), status = $('status');

function setStatus(msg, error = false) { status.textContent = msg; status.style.color = error ? '#b42318' : '#556070'; }
function validateInput() {
  if (!input.value.trim()) { setStatus('Please enter text first.', true); return false; }
  if (!algorithm.value) { setStatus('Please select a method.', true); return false; }
  return true;
}
function updateParameter() {
  const a = algorithm.value;
  const configs = {
    caesar: ['Caesar Shift', '3', 'number'],
    vigenere: ['Vigenere Key', 'SECRET', 'text'],
    xor: ['XOR Key', 'mysecret', 'text'],
    railfence: ['Number of Rails', '3', 'number']
  };
  if (configs[a]) {
    $('parameterBox').style.display = 'block';
    parameterLabel.textContent = configs[a][0];
    parameter.placeholder = configs[a][1];
    parameter.value = configs[a][1];
    parameter.type = configs[a][2];
  } else if (a === 'rsa') {
    $('parameterBox').style.display = 'block';
    parameterLabel.textContent = 'RSA Key';
    parameter.placeholder = 'Generated automatically on server';
    parameter.value = 'Automatic 2048-bit key pair';
    parameter.type = 'text';
  } else if (a === 'aes') {
    $('parameterBox').style.display = 'block';
    parameterLabel.textContent = 'AES Key';
    parameter.placeholder = 'Built-in assignment key';
    parameter.value = 'Built-in 256-bit key';
    parameter.type = 'text';
  } else {
    $('parameterBox').style.display = 'none';
    parameter.value = '';
  }
}
async function request(url, body) {
  const response = await fetch(url, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}
function getBody() {
  return {
    text: input.value,
    algorithm: algorithm.value,
    shift: algorithm.value === 'caesar' ? parameter.value : undefined,
    key: ['vigenere', 'xor'].includes(algorithm.value) ? parameter.value : undefined,
    rails: algorithm.value === 'railfence' ? parameter.value : undefined
  };
}
$('encryptBtn').onclick = async () => {
  if (!validateInput()) return;
  if (['sha256', 'sha512', 'md5'].includes(algorithm.value)) { setStatus('Hash methods use the Hash button.', true); return; }
  try { const data = await request('/api/encrypt', getBody()); output.value = data.ciphertext; setStatus('Encryption completed successfully.'); }
  catch (e) { setStatus(e.message, true); }
};
$('decryptBtn').onclick = async () => {
  if (!validateInput()) return;
  if (['sha256', 'sha512', 'md5'].includes(algorithm.value)) { setStatus('Hashes cannot be decrypted.', true); return; }
  try { const data = await request('/api/decrypt', getBody()); output.value = data.plaintext; setStatus('Decryption completed successfully.'); }
  catch (e) { setStatus(e.message, true); }
};
$('hashBtn').onclick = async () => {
  if (!input.value.trim()) { setStatus('Please enter text first.', true); return; }
  let hashAlgorithm = algorithm.value;
  if (!['sha256', 'sha512', 'md5'].includes(hashAlgorithm)) hashAlgorithm = 'sha256';
  try { const data = await request('/api/hash', {text: input.value, hashAlgorithm}); output.value = data.hash; setStatus(`${hashAlgorithm.toUpperCase()} hash generated.`); }
  catch (e) { setStatus(e.message, true); }
};
$('copyBtn').onclick = async () => {
  if (!output.value) { setStatus('There is no result to copy.', true); return; }
  await navigator.clipboard.writeText(output.value); setStatus('Result copied to clipboard.');
};
algorithm.onchange = updateParameter;
updateParameter();
