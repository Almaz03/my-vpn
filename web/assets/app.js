(() => {
  'use strict';

  const PLATFORM_NAMES = {
    android: 'Android',
    ios: 'iPhone / iPad',
    windows: 'Windows',
    macos: 'macOS',
    linux: 'Linux'
  };

  const PLATFORM_HINTS = {
    android: 'Установите AmneziaVPN из официального источника. Android попросит разрешить VPN-подключение.',
    ios: 'Установите AmneziaVPN, скачайте профиль и импортируйте его из файла.',
    windows: 'Установите AmneziaVPN для Windows и импортируйте скачанный файл.',
    macos: 'Установите AmneziaVPN для macOS и импортируйте скачанный файл.',
    linux: 'Откройте официальный сайт AmneziaVPN и выберите пакет для вашего дистрибутива.'
  };

  const form = document.querySelector('#activation-form');
  const codeInput = document.querySelector('#invite-code');
  const submitButton = document.querySelector('#submit-button');
  const statusBox = document.querySelector('#status');
  const platformLabel = document.querySelector('#platform-label');
  const platformPicker = document.querySelector('#platform-picker');
  const changePlatform = document.querySelector('#change-platform');
  const activationPanel = document.querySelector('#activation-panel');
  const resultPanel = document.querySelector('#result-panel');
  const resultTitle = document.querySelector('#result-title');
  const resultMessage = document.querySelector('#result-message');
  const installHint = document.querySelector('#install-hint');
  const importHint = document.querySelector('#import-hint');
  const openAmnezia = document.querySelector('#open-amnezia');
  const downloadLink = document.querySelector('#download-link');
  const qrStep = document.querySelector('#qr-step');
  const qrImage = document.querySelector('#qr-image');
  const showRequestForm = document.querySelector('#show-request-form');
  const accessRequestPanel = document.querySelector('#access-request-panel');
  const accessRequestForm = document.querySelector('#access-request-form');
  const requestName = document.querySelector('#request-name');
  const requestDevice = document.querySelector('#request-device');
  const requestSubmit = document.querySelector('#request-submit');
  const requestStatus = document.querySelector('#request-status');
  const approvedCodePanel = document.querySelector('#approved-code-panel');
  const approvedCode = document.querySelector('#approved-code');
  const approvedCodeExpiry = document.querySelector('#approved-code-expiry');
  const copyApprovedCode = document.querySelector('#copy-approved-code');
  const useApprovedCode = document.querySelector('#use-approved-code');

  let platform = detectPlatform();
  let nextAttemptAt = 0;
  let requestToken = '';
  let pollTimer = 0;
  let configFile = null;
  let configDownloadUrl = '';

  selectPlatform(platform);

  try {
    const saved = sessionStorage.getItem('accessRequestToken') || '';
    if (/^[A-Za-z0-9_-]{43}$/.test(saved)) {
      requestToken = saved;
      openRequestPanel();
      setRequestBusy(true);
      showRequestStatus('Проверяем состояние запроса…', 'busy');
      pollAccessRequest();
    }
  } catch {
    // The flow still works when browser storage is unavailable.
  }

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && requestToken) {
      showRequestStatus('Проверяем решение администратора…', 'busy');
      pollAccessRequest();
    }
  });

  window.addEventListener('online', () => {
    if (requestToken) {
      showRequestStatus('Связь восстановлена. Проверяем запрос…', 'busy');
      pollAccessRequest();
    }
  });

  openAmnezia.addEventListener('click', async () => {
    if (!configDownloadUrl) return;
    if (configFile && navigator.share && navigator.canShare && navigator.canShare({ files: [configFile] })) {
      try {
        await navigator.share({ files: [configFile], title: 'Family VPN' });
        return;
      } catch (error) {
        if (error && error.name === 'AbortError') return;
      }
    }
    downloadLink.click();
    importHint.textContent = 'Файл скачан. Откройте его и выберите AmneziaVPN в меню «Поделиться».';
  });

  showRequestForm.addEventListener('click', () => {
    if (accessRequestPanel.hidden) {
      openRequestPanel();
      requestName.focus();
    } else if (!requestToken) {
      accessRequestPanel.hidden = true;
      showRequestForm.setAttribute('aria-expanded', 'false');
    }
  });

  accessRequestForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const relativeName = requestName.value.trim();
    const deviceName = requestDevice.value.trim();
    if (!relativeName || !deviceName || [...relativeName].length > 100 || [...deviceName].length > 100) {
      showRequestStatus('Заполните имя и название устройства (до 100 символов).', 'error');
      return;
    }
    setRequestBusy(true);
    showRequestStatus('Отправляем запрос администратору…', 'busy');
    try {
      const response = await fetch('/api/v1/access-requests', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
        body: JSON.stringify({relative_name: relativeName, device_name: deviceName, platform})
      });
      const data = await readJson(response);
      if (!response.ok) {
        if (response.status === 400 || response.status === 404) {
          clearAccessRequestToken();
          setRequestBusy(false);
          showRequestStatus(requestError(response.status, data), 'error');
          return;
        }
        throw new Error(requestError(response.status, data));
      }
      if (typeof data.request_token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.request_token)) {
        throw new Error('Сервис вернул некорректный ответ. Повторите позже.');
      }
      requestToken = data.request_token;
      try { sessionStorage.setItem('accessRequestToken', requestToken); } catch { /* optional */ }
      showRequestStatus('Запрос отправлен. Ожидаем решение администратора — страницу можно не закрывать.', 'busy');
      pollAccessRequest();
    } catch (error) {
      setRequestBusy(false);
      showRequestStatus(error instanceof Error ? error.message : 'Не удалось отправить запрос.', 'error');
    }
  });

  copyApprovedCode.addEventListener('click', async () => {
    if (!approvedCode.textContent) return;
    const copied = await copyText(approvedCode.textContent);
    copyApprovedCode.textContent = copied ? 'Код скопирован' : 'Выделите код выше';
  });

  useApprovedCode.addEventListener('click', () => {
    const code = approvedCode.textContent.trim();
    if (!/^[A-Z0-9-]{4,16}$/.test(code)) return;
    codeInput.value = code;
    accessRequestPanel.hidden = true;
    showRequestForm.setAttribute('aria-expanded', 'false');
    codeInput.focus();
    form.requestSubmit();
  });

  changePlatform.addEventListener('click', () => {
    const willOpen = platformPicker.hidden;
    platformPicker.hidden = !willOpen;
    changePlatform.setAttribute('aria-expanded', String(willOpen));
  });

  platformPicker.addEventListener('change', (event) => {
    if (event.target instanceof HTMLInputElement && event.target.name === 'platform') {
      selectPlatform(event.target.value);
    }
  });

  codeInput.addEventListener('input', () => {
    const caret = codeInput.selectionStart;
    codeInput.value = codeInput.value.replace(/[^A-Za-z0-9-]/g, '').toUpperCase();
    if (caret !== null) codeInput.setSelectionRange(caret, caret);
    clearStatus();
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    const now = Date.now();
    if (now < nextAttemptAt) {
      showStatus('Подождите несколько секунд перед повторной попыткой.', 'error');
      return;
    }

    const code = codeInput.value.trim().toUpperCase();
    if (!/^[A-Z0-9-]{4,16}$/.test(code)) {
      showStatus('Проверьте код: допустимы латинские буквы, цифры и дефис.', 'error');
      codeInput.focus();
      return;
    }

    setBusy(true);
    showStatus('Проверяем приглашение и создаём отдельный профиль устройства…', 'busy');

    try {
      const response = await fetch('/api/v1/activate', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ code, platform })
      });

      codeInput.value = '';
      const data = await readJson(response);

      if (!response.ok) {
        nextAttemptAt = Date.now() + retryDelay(response);
        throw new Error(publicError(response.status, data));
      }

      renderResult(data);
    } catch (error) {
      codeInput.value = '';
      const message = error instanceof Error && error.message
        ? error.message
        : 'Не удалось проверить приглашение. Попробуйте позже.';
      showStatus(message, 'error');
      codeInput.focus();
    } finally {
      setBusy(false);
    }
  });

  function detectPlatform() {
    const ua = navigator.userAgent.toLowerCase();
    const platformName = (navigator.userAgentData?.platform || navigator.platform || '').toLowerCase();
    if (/android/.test(ua)) return 'android';
    if (/iphone|ipad|ipod/.test(ua) || (platformName === 'macintel' && navigator.maxTouchPoints > 1)) return 'ios';
    if (/win/.test(platformName) || /windows/.test(ua)) return 'windows';
    if (/mac/.test(platformName) || /macintosh/.test(ua)) return 'macos';
    return 'linux';
  }

  function selectPlatform(value) {
    platform = Object.hasOwn(PLATFORM_NAMES, value) ? value : 'linux';
    platformLabel.textContent = PLATFORM_NAMES[platform];
    const radio = platformPicker.querySelector(`input[value="${platform}"]`);
    if (radio) radio.checked = true;
  }

  function setBusy(busy) {
    submitButton.disabled = busy;
    codeInput.disabled = busy;
    submitButton.textContent = busy ? 'Подключаем…' : 'Продолжить';
    form.setAttribute('aria-busy', String(busy));
  }

  function showStatus(message, kind) {
    statusBox.textContent = message;
    statusBox.className = `status status--${kind}`;
    statusBox.hidden = false;
  }

  function clearStatus() {
    statusBox.hidden = true;
    statusBox.textContent = '';
    statusBox.className = 'status';
  }

  async function readJson(response) {
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('application/json')) return {};
    try {
      return await response.json();
    } catch {
      return {};
    }
  }

  function retryDelay(response) {
    const retryAfter = Number.parseInt(response.headers.get('retry-after') || '', 10);
    if (Number.isFinite(retryAfter) && retryAfter > 0) return Math.min(retryAfter, 60) * 1000;
    return 3000;
  }

  function publicError(status, data) {
    if (status === 429) return 'Слишком много попыток. Подождите и попробуйте снова.';
    if (status === 400) return 'Проверьте формат кода приглашения.';
    if (status === 409 && typeof data.error === 'string' && data.error.length <= 180) return data.error;
    if (status === 404 || status === 409 || status === 410) return 'Код недействителен, уже использован или истёк. Попросите новый код.';
    if (status >= 500) return 'Сервис временно недоступен. Попробуйте позже.';
    if (typeof data.error === 'string' && data.error.length <= 180) return data.error;
    return 'Не удалось активировать приглашение.';
  }

  function openRequestPanel() {
    accessRequestPanel.hidden = false;
    showRequestForm.setAttribute('aria-expanded', 'true');
  }

  function setRequestBusy(busy) {
    requestName.disabled = busy;
    requestDevice.disabled = busy;
    requestSubmit.disabled = busy;
    requestSubmit.textContent = busy ? 'Ожидаем решение…' : 'Отправить запрос';
    accessRequestForm.setAttribute('aria-busy', String(busy));
  }

  function showRequestStatus(message, kind) {
    requestStatus.textContent = message;
    requestStatus.className = `status status--${kind}`;
    requestStatus.hidden = false;
  }

  function requestError(status, data) {
    if (typeof data.error === 'string' && data.error.length <= 180) return data.error;
    if (status === 409) return 'Для этого имени уже зарегистрировано устройство.';
    if (status === 429) return 'Слишком много запросов. Повторите через час.';
    if (status >= 500) return 'Сервис временно недоступен. Повторите позже.';
    return 'Проверьте имя и название устройства.';
  }

  async function pollAccessRequest() {
    window.clearTimeout(pollTimer);
    if (!requestToken) return;
    try {
      const response = await fetch('/api/v1/access-requests/status', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
        body: JSON.stringify({request_token: requestToken})
      });
      const data = await readJson(response);
      if (!response.ok) {
        if (response.status === 400 || response.status === 404) {
          clearAccessRequestToken();
          setRequestBusy(false);
          showRequestStatus(requestError(response.status, data), 'error');
          return;
        }
        throw new Error(requestError(response.status, data));
      }
      if (data.state === 'approved' && typeof data.code === 'string' && /^[A-Z0-9-]{4,16}$/.test(data.code)) {
        approvedCode.textContent = data.code;
        approvedCodeExpiry.textContent = `Код действует до ${formatExpiry(data.expires_at)} и используется один раз.`;
        approvedCodePanel.hidden = false;
        showRequestStatus('Доступ одобрен. Скопируйте код или сразу подключите устройство.', 'success');
        return;
      }
      if (data.state === 'denied') {
        clearAccessRequestToken();
        setRequestBusy(false);
        showRequestStatus('Администратор отклонил запрос.', 'error');
        return;
      }
      if (data.state === 'expired') {
        clearAccessRequestToken();
        setRequestBusy(false);
        showRequestStatus('Время ожидания истекло. Можно отправить новый запрос.', 'error');
        return;
      }
      showRequestStatus('Запрос отправлен. Ожидаем решение администратора…', 'busy');
      pollTimer = window.setTimeout(pollAccessRequest, 3000);
    } catch (error) {
      showRequestStatus('Связь временно прервалась. Запрос сохранён, продолжаем ждать…', 'busy');
      pollTimer = window.setTimeout(pollAccessRequest, 5000);
    }
  }

  function clearAccessRequestToken() {
    requestToken = '';
    try { sessionStorage.removeItem('accessRequestToken'); } catch { /* optional */ }
  }

  function formatExpiry(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'указанного времени' : date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
  }

  async function copyText(value) {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(value);
        return true;
      } catch { /* use selection fallback */ }
    }
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(approvedCode);
    selection.removeAllRanges();
    selection.addRange(range);
    return false;
  }

  function renderResult(data) {
    clearAccessRequestToken();
    clearStatus();
    const downloadUrl = safeLocalUrl(data.config_download_url);
    const qrUrl = safeImageUrl(data.qr_code_url);
    const profileAvailable = Boolean(downloadUrl || qrUrl);
    configDownloadUrl = downloadUrl;
    configFile = null;

    resultTitle.textContent = profileAvailable ? 'Профиль устройства готов' : 'Приглашение принято';
    resultMessage.textContent = typeof data.message === 'string' && data.message.length <= 180
      ? data.message
      : profileAvailable
        ? 'Установите AmneziaVPN и импортируйте созданный профиль.'
        : 'Профиль ещё не выдан. Администратор завершит подготовку подключения.';
    installHint.textContent = PLATFORM_HINTS[platform];
    importHint.textContent = profileAvailable
      ? 'Операционная система или приложение могут попросить подтверждение — это нормальная мера безопасности.'
      : 'Кнопка импорта появится после безопасного создания отдельного профиля для устройства.';

    downloadLink.hidden = !downloadUrl;
    if (downloadUrl) downloadLink.href = downloadUrl;
    openAmnezia.hidden = !downloadUrl;
    openAmnezia.disabled = false;
    openAmnezia.textContent = 'Открыть в AmneziaVPN';
    if (downloadUrl) prepareConfigShare(downloadUrl);

    qrStep.hidden = !qrUrl;
    if (qrUrl) qrImage.src = qrUrl;
    activationPanel.hidden = true;
    resultPanel.hidden = false;
    resultPanel.focus({ preventScroll: true });
    resultPanel.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
  }

  async function prepareConfigShare(downloadUrl) {
    if (!navigator.share || !navigator.canShare || typeof File !== 'function') return;
    openAmnezia.disabled = true;
    openAmnezia.textContent = 'Подготавливаем профиль…';
    try {
      const response = await fetch(downloadUrl, { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error('profile unavailable');
      const body = await response.text();
      if (body.length < 100 || body.length > 32768 || !body.includes('[Interface]') || !body.includes('[Peer]')) {
        throw new Error('invalid profile');
      }
      const file = new File([body], 'family-vpn.conf', { type: 'text/plain' });
      if (configDownloadUrl === downloadUrl && navigator.canShare({ files: [file] })) configFile = file;
    } catch {
      configFile = null;
    } finally {
      if (configDownloadUrl === downloadUrl) {
        openAmnezia.disabled = false;
        openAmnezia.textContent = 'Открыть в AmneziaVPN';
      }
    }
  }

  function safeLocalUrl(value) {
    if (typeof value !== 'string' || value.length > 2048) return '';
    try {
      const url = new URL(value, window.location.origin);
      return url.origin === window.location.origin && url.protocol === window.location.protocol ? url.href : '';
    } catch {
      return '';
    }
  }

  function safeImageUrl(value) {
    if (typeof value === 'string' && /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(value) && value.length < 500000) return value;
    return safeLocalUrl(value);
  }

  function prefersReducedMotion() {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }
})();
