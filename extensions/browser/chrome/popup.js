const stateEl = document.getElementById('state');
const proxyEl = document.getElementById('proxy');
const coreEl = document.getElementById('core');
const errorEl = document.getElementById('error');
const inputEl = document.getElementById('profileInput');
const importButton = document.getElementById('importButton');
const connectButton = document.getElementById('connectButton');
const disconnectButton = document.getElementById('disconnectButton');

importButton.addEventListener('click', () => run(async () => {
  await send({ type: 'importProfile', input: inputEl.value });
  await refresh();
}));

connectButton.addEventListener('click', () => run(async () => {
  await send({ type: 'connect', input: inputEl.value.trim() || undefined });
  await refresh();
}));

disconnectButton.addEventListener('click', () => run(async () => {
  await send({ type: 'disconnect' });
  await refresh();
}));

refresh();

async function refresh() {
  await run(async () => {
    const status = await send({ type: 'status' });
    renderStatus(status);
  }, { silent: true });
}

async function run(action, options = {}) {
  errorEl.textContent = '';
  setBusy(true);
  try {
    await action();
  } catch (error) {
    if (!options.silent) {
      errorEl.textContent = String(error.message || error);
    } else {
      stateEl.textContent = 'companion offline';
      proxyEl.textContent = 'not connected';
      coreEl.textContent = '-';
    }
  } finally {
    setBusy(false);
  }
}

function send(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (reply) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      if (!reply?.ok) {
        reject(new Error(reply?.error || 'Extension request failed.'));
        return;
      }
      resolve(reply.response?.response || reply.response);
    });
  });
}

function renderStatus(status) {
  stateEl.textContent = status.state || 'UNKNOWN';
  const endpoint = status.proxyEndpoint;
  proxyEl.textContent = endpoint
    ? `${endpoint.scheme}://${endpoint.host}:${endpoint.port}`
    : '-';
  coreEl.textContent = status.coreVersion || '-';
}

function setBusy(busy) {
  importButton.disabled = busy;
  connectButton.disabled = busy;
  disconnectButton.disabled = busy;
}
