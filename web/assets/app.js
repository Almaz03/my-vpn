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
    android: 'Установите INCY из официального источника. Android попросит разрешить VPN-подключение.',
    ios: 'Установите INCY, затем подтвердите добавление VPN-конфигурации в iOS или iPadOS.',
    windows: 'Установите INCY для Windows и подтвердите импорт профиля в приложении.',
    macos: 'Установите INCY для macOS и разрешите добавление VPN-конфигурации в настройках системы.',
    linux: 'Откройте официальный сайт INCY и выберите поддерживаемый пакет для вашего дистрибутива.'
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
  const importButton = document.querySelector('#import-button');
  const downloadLink = document.querySelector('#download-link');
  const qrStep = document.querySelector('#qr-step');
  const qrImage = document.querySelector('#qr-image');

  let platform = detectPlatform();
  let deepLink = '';
  let nextAttemptAt = 0;

  selectPlatform(platform);

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

  importButton.addEventListener('click', () => {
    if (!deepLink) return;
    window.location.assign(deepLink);
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
    if (status === 404 || status === 409 || status === 410) return 'Код недействителен, уже использован или истёк. Попросите новый код.';
    if (status >= 500) return 'Сервис временно недоступен. Попробуйте позже.';
    if (typeof data.message === 'string' && data.message.length <= 180) return data.message;
    return 'Не удалось активировать приглашение.';
  }

  function renderResult(data) {
    clearStatus();
    deepLink = safeDeepLink(data.incy_deep_link);
    const downloadUrl = safeLocalUrl(data.config_download_url);
    const qrUrl = safeImageUrl(data.qr_code_url);
    const profileAvailable = Boolean(deepLink || downloadUrl || qrUrl);

    resultTitle.textContent = profileAvailable ? 'Профиль устройства готов' : 'Приглашение принято';
    resultMessage.textContent = typeof data.message === 'string' && data.message.length <= 180
      ? data.message
      : profileAvailable
        ? 'Установите INCY и импортируйте созданный профиль.'
        : 'Профиль ещё не выдан. Администратор завершит подготовку подключения.';
    installHint.textContent = PLATFORM_HINTS[platform];
    importHint.textContent = profileAvailable
      ? 'Операционная система или приложение могут попросить подтверждение — это нормальная мера безопасности.'
      : 'Кнопка импорта появится после безопасного создания отдельного профиля для устройства.';

    importButton.hidden = !deepLink;
    downloadLink.hidden = !downloadUrl;
    if (downloadUrl) downloadLink.href = downloadUrl;

    qrStep.hidden = !qrUrl;
    if (qrUrl) qrImage.src = qrUrl;

    activationPanel.hidden = true;
    resultPanel.hidden = false;
    resultPanel.focus({ preventScroll: true });
    resultPanel.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
  }

  function safeDeepLink(value) {
    if (typeof value !== 'string' || value.length > 4096) return '';
    return /^incy:\/\/[A-Za-z0-9._~!$&'()*+,;=:@/?%-]+$/.test(value) ? value : '';
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
