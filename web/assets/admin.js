(() => {
  'use strict';

  const loginPanel = document.querySelector('#login-panel');
  const loginForm = document.querySelector('#login-form');
  const tokenInput = document.querySelector('#admin-token');
  const loginStatus = document.querySelector('#login-status');
  const adminPanel = document.querySelector('#admin-panel');
  const logoutButton = document.querySelector('#logout-button');
  const refreshButton = document.querySelector('#refresh-button');
  const inviteForm = document.querySelector('#invite-form');
  const inviteStatus = document.querySelector('#invite-status');
  const inviteResult = document.querySelector('#invite-result');
  const inviteCodeResult = document.querySelector('#invite-code-result');
  const inviteExpiry = document.querySelector('#invite-expiry');
  const copyCodeButton = document.querySelector('#copy-code-button');
  const revokeInviteButton = document.querySelector('#revoke-invite-button');
  const devicesStatus = document.querySelector('#devices-status');
  const deviceList = document.querySelector('#device-list');
  const serviceStatus = document.querySelector('#service-status');
  const statusGrid = document.querySelector('#status-grid');

  let adminToken = '';
  let currentInvitationID = '';

  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const candidate = tokenInput.value;
    tokenInput.value = '';
    if (candidate.length < 24) {
      show(loginStatus, 'Токен слишком короткий.', 'error');
      return;
    }
    adminToken = candidate;
    if (!(await loadDevices())) {
      adminToken = '';
      show(loginStatus, 'Токен не принят или сервис недоступен.', 'error');
      tokenInput.focus();
      return;
    }
    hide(loginStatus);
    loginPanel.hidden = true;
    adminPanel.hidden = false;
    await loadStatus();
  });

  logoutButton.addEventListener('click', () => {
    adminToken = '';
    currentInvitationID = '';
    inviteCodeResult.textContent = '';
    inviteResult.hidden = true;
    deviceList.replaceChildren();
    statusGrid.replaceChildren();
    adminPanel.hidden = true;
    loginPanel.hidden = false;
    tokenInput.focus();
  });

  refreshButton.addEventListener('click', async () => {
    refreshButton.disabled = true;
    try {
      await Promise.all([loadDevices(), loadStatus()]);
    } finally {
      refreshButton.disabled = false;
    }
  });

  inviteForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    hide(inviteStatus);
    inviteResult.hidden = true;
    inviteCodeResult.textContent = '';
    const relativeName = document.querySelector('#relative-name').value.trim();
    const deviceName = document.querySelector('#device-name').value.trim();
    const ttlSeconds = Number.parseInt(document.querySelector('#invite-ttl').value, 10);
    try {
      const response = await api('/api/v1/admin/invitations', {
        method: 'POST',
        body: JSON.stringify({ relative_name: relativeName, device_name: deviceName, ttl_seconds: ttlSeconds })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(publicError(response.status));
      const code = typeof data.code === 'string' ? data.code : '';
      const invitation = data.invitation && typeof data.invitation === 'object' ? data.invitation : {};
      if (!code || typeof invitation.id !== 'string') throw new Error('Сервис вернул неполный ответ.');
      currentInvitationID = invitation.id;
      inviteCodeResult.textContent = code;
      inviteExpiry.textContent = invitation.expires_at
        ? `Действует до ${formatDate(invitation.expires_at)}.`
        : 'Код действует ограниченное время.';
      inviteResult.hidden = false;
    } catch (error) {
      show(inviteStatus, error instanceof Error ? error.message : 'Не удалось создать приглашение.', 'error');
    }
  });

  copyCodeButton.addEventListener('click', async () => {
    const code = inviteCodeResult.textContent || '';
    if (!code || !navigator.clipboard || !window.isSecureContext) return;
    try {
      await navigator.clipboard.writeText(code);
      copyCodeButton.textContent = 'Код скопирован';
    } catch {
      copyCodeButton.textContent = 'Не удалось скопировать';
    }
  });

  revokeInviteButton.addEventListener('click', async () => {
    if (!currentInvitationID) return;
    if (!window.confirm('Отозвать это приглашение? Код больше нельзя будет использовать.')) return;
    revokeInviteButton.disabled = true;
    try {
      const response = await api(`/api/v1/admin/invitations/${encodeURIComponent(currentInvitationID)}/revoke`, { method: 'POST' });
      if (!response.ok) throw new Error(publicError(response.status));
      currentInvitationID = '';
      inviteCodeResult.textContent = '';
      inviteResult.hidden = true;
      show(inviteStatus, 'Приглашение отозвано.', 'busy');
    } catch (error) {
      show(inviteStatus, error instanceof Error ? error.message : 'Не удалось отозвать приглашение.', 'error');
    } finally {
      revokeInviteButton.disabled = false;
    }
  });

  async function loadDevices() {
    hide(devicesStatus);
    try {
      const response = await api('/api/v1/admin/devices');
      const data = await response.json();
      if (!response.ok) throw new Error(publicError(response.status));
      renderDevices(Array.isArray(data.devices) ? data.devices : []);
      return true;
    } catch (error) {
      show(devicesStatus, error instanceof Error ? error.message : 'Не удалось загрузить устройства.', 'error');
      return false;
    }
  }

  function renderDevices(devices) {
    deviceList.replaceChildren();
    if (devices.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'hint';
      empty.textContent = 'Подключённых устройств пока нет.';
      deviceList.append(empty);
      return;
    }
    for (const device of devices) {
      if (!device || typeof device.id !== 'string') continue;
      const item = document.createElement('article');
      item.className = 'device';
      const info = document.createElement('div');
      const title = document.createElement('h3');
      title.textContent = `${safeText(device.relative_name, 'Без имени')} — ${safeText(device.device_name, 'Устройство')}`;
      const state = document.createElement('span');
      state.className = `state-pill${device.state === 'revoked' ? ' state-pill--revoked' : ''}`;
      state.textContent = stateName(device.state);
      title.append(state);
      const details = document.createElement('p');
      details.textContent = `${platformName(device.platform)} · создано ${formatDate(device.created_at)}`;
      info.append(title, details);
      item.append(info);
      if (device.state !== 'revoked') {
        const revoke = document.createElement('button');
        revoke.className = 'danger-button';
        revoke.type = 'button';
        revoke.textContent = 'Отозвать';
        revoke.addEventListener('click', () => revokeDevice(device.id, revoke));
        item.append(revoke);
      }
      deviceList.append(item);
    }
  }

  async function revokeDevice(id, button) {
    if (!window.confirm('Отозвать доступ этого устройства? Подключение перестанет работать.')) return;
    button.disabled = true;
    try {
      const response = await api(`/api/v1/admin/devices/${encodeURIComponent(id)}/revoke`, { method: 'POST' });
      if (!response.ok) throw new Error(publicError(response.status));
      await loadDevices();
    } catch (error) {
      show(devicesStatus, error instanceof Error ? error.message : 'Не удалось отозвать устройство.', 'error');
      button.disabled = false;
    }
  }

  async function loadStatus() {
    hide(serviceStatus);
    statusGrid.replaceChildren();
    try {
      const response = await api('/api/v1/admin/status');
      const contentType = response.headers.get('content-type') || '';
      if (response.status === 404 || !contentType.toLowerCase().includes('application/json')) {
        show(serviceStatus, 'Расширенная диагностика ещё не подключена. Портал и база доступны.', 'busy');
        return;
      }
      const data = await response.json();
      if (!response.ok) throw new Error(publicError(response.status));
      const preferred = ['portal', 'vpn', 'certificate', 'cpu', 'memory', 'disk', 'network'];
      const entries = preferred.filter((key) => Object.hasOwn(data, key)).map((key) => [key, data[key]]);
      for (const [key, value] of entries) {
        const metric = document.createElement('div');
        metric.className = 'status-metric';
        const label = document.createElement('span');
        label.textContent = statusLabel(key);
        const output = document.createElement('strong');
        output.textContent = safeText(value, '—');
        metric.append(label, output);
        statusGrid.append(metric);
      }
      if (entries.length === 0) show(serviceStatus, 'Сервис работает, подробных метрик нет.', 'busy');
    } catch (error) {
      show(serviceStatus, error instanceof Error ? error.message : 'Не удалось получить состояние.', 'error');
    }
  }

  function api(path, options = {}) {
    return fetch(path, {
      ...options,
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: {
        'Accept': 'application/json',
        'Authorization': `Bearer ${adminToken}`,
        ...(options.body ? { 'Content-Type': 'application/json' } : {})
      }
    });
  }

  function publicError(status) {
    if (status === 401) return 'Токен не принят.';
    if (status === 404) return 'Запись не найдена или уже отозвана.';
    if (status === 429) return 'Слишком много операций. Подождите и попробуйте снова.';
    if (status >= 500) return 'Сервис временно недоступен.';
    return 'Операция не выполнена.';
  }

  function show(element, message, kind) {
    element.textContent = message;
    element.className = `status status--${kind}`;
    element.hidden = false;
  }

  function hide(element) {
    element.hidden = true;
    element.textContent = '';
    element.className = 'status';
  }

  function safeText(value, fallback) {
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
    return typeof value === 'string' && value.length <= 160 ? value : fallback;
  }

  function formatDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'неизвестно' : date.toLocaleString('ru-RU');
  }

  function platformName(value) {
    return { android: 'Android', ios: 'iPhone / iPad', windows: 'Windows', macos: 'macOS', linux: 'Linux' }[value] || 'Неизвестная платформа';
  }

  function stateName(value) {
    return { active: 'активно', pending: 'ожидает', revoke_pending: 'отзыв ожидает', revoked: 'отозвано' }[value] || 'неизвестно';
  }

  function statusLabel(key) {
    return { portal: 'Портал', vpn: 'VPN', certificate: 'Сертификат', cpu: 'CPU', memory: 'Память', disk: 'Диск', network: 'Сеть' }[key] || key;
  }
})();
