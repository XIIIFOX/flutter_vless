const NATIVE_HOST = 'dev.tfox.flutter_vless';

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  handleMessage(message)
    .then((response) => sendResponse({ ok: true, response }))
    .catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));
  return true;
});

async function handleMessage(message) {
  switch (message?.type) {
    case 'status':
      return nativeRequest({ type: 'status' });
    case 'importProfile':
      return nativeRequest({ type: 'importProfile', input: message.input });
    case 'connect': {
      const connected = await nativeRequest({
        type: 'connect',
        profileId: message.profileId,
        input: message.input,
        setSystemProxy: false
      });
      const endpoint = connected.proxyEndpoint || connected.response?.proxyEndpoint;
      await setBrowserProxy(endpoint);
      return connected;
    }
    case 'disconnect': {
      const disconnected = await nativeRequest({ type: 'disconnect' });
      await clearBrowserProxy();
      return disconnected;
    }
    case 'clearBrowserProxy':
      await clearBrowserProxy();
      return { cleared: true };
    default:
      throw new Error(`Unsupported message: ${message?.type}`);
  }
}

function nativeRequest(payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, payload, (reply) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      if (!reply?.ok) {
        reject(new Error(reply?.error || 'Native host request failed.'));
        return;
      }
      resolve(reply.response);
    });
  });
}

async function setBrowserProxy(endpoint) {
  if (!endpoint?.host || !endpoint?.port || !endpoint?.scheme) {
    throw new Error('Companion did not provide a proxy endpoint.');
  }

  const config = {
    mode: 'fixed_servers',
    rules: {
      singleProxy: {
        scheme: endpoint.scheme,
        host: endpoint.host,
        port: endpoint.port
      },
      bypassList: ['localhost', '127.0.0.1', '<local>']
    }
  };

  await proxySettingsSet({
    value: config,
    scope: 'regular'
  });
  await storageSet({ proxyEndpoint: endpoint, proxyEnabled: true });
}

async function clearBrowserProxy() {
  await proxySettingsClear({ scope: 'regular' });
  await storageSet({ proxyEnabled: false });
}

function proxySettingsSet(details) {
  return new Promise((resolve, reject) => {
    chrome.proxy.settings.set(details, () => {
      const error = chrome.runtime.lastError;
      error ? reject(new Error(error.message)) : resolve();
    });
  });
}

function proxySettingsClear(details) {
  return new Promise((resolve, reject) => {
    chrome.proxy.settings.clear(details, () => {
      const error = chrome.runtime.lastError;
      error ? reject(new Error(error.message)) : resolve();
    });
  });
}

function storageSet(values) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set(values, () => {
      const error = chrome.runtime.lastError;
      error ? reject(new Error(error.message)) : resolve();
    });
  });
}
