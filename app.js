/* =========================================================
   N1 Credentials Generator — app.js v2.0
   =========================================================
   Módulos:
     1. CSPRNG — Generación criptográficamente segura
     2. Tema — Light / Dark mode
     3. Entidad — Selector de prefijo
     4. Slider — Longitud con slider
     5. Palabra Clave — Input con sanitización
     6. Generador — Lógica principal de contraseña
     7. Entropía — Cálculo matemático de bits
     8. Visibilidad — Mostrar / Ocultar contraseña
     9. Clipboard — Copia manual + Autocopiado
    10. Toast — Notificaciones
    11. Init — Inicialización
   ========================================================= */


/* ─────────────────────────────────────────────────────────
   1. CSPRNG — Sin modulo bias (2^32 exacto)
   ───────────────────────────────────────────────────────── */

/**
 * Retorna un índice aleatorio seguro en [0, poolLength)
 * usando rechazo de zona sesgada para garantizar uniformidad.
 * @param {number} poolLength
 * @returns {number}
 */
function secureRandIndex(poolLength) {
    if (poolLength <= 0) throw new RangeError("poolLength debe ser > 0");
    const RANGE = 4294967296; // 2^32
    const maxValid = RANGE - (RANGE % poolLength);
    const buf = new Uint32Array(1);
    let attempts = 0;
    do {
        window.crypto.getRandomValues(buf);
        if (++attempts > 1000) throw new Error("CSPRNG: demasiados re-rolls (pool inválido)");
    } while (buf[0] >= maxValid);
    return buf[0] % poolLength;
}

/**
 * Fisher-Yates shuffle criptográfico in-place.
 * @param {Array} arr
 * @returns {Array} el mismo array mezclado
 */
function secureShuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = secureRandIndex(i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}


/* ─────────────────────────────────────────────────────────
   2. TEMA — Light / Dark mode
   ───────────────────────────────────────────────────────── */

const THEME_KEY = 'n1-theme';

function initTheme() {
    const saved = localStorage.getItem(THEME_KEY);
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = saved || (prefersDark ? 'dark' : 'light');
    applyTheme(theme);
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    applyTheme(current === 'dark' ? 'light' : 'dark');
}

document.getElementById('theme-toggle').addEventListener('click', toggleTheme);


/* ─────────────────────────────────────────────────────────
   3. ENTIDAD — Selector de prefijo
   ───────────────────────────────────────────────────────── */

let selectedPrefix = 'Hp'; // Valor por defecto

function initEntitySelector() {
    const buttons = document.querySelectorAll('.entity-btn');
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            buttons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            selectedPrefix = btn.dataset.prefix;
        });
    });
}


/* ─────────────────────────────────────────────────────────
   4. SLIDER — Longitud
   ───────────────────────────────────────────────────────── */

function initSlider() {
    const slider  = document.getElementById('length-slider');
    const display = document.getElementById('length-value-display');

    function updateDisplay() {
        display.textContent = slider.value;
        // Colorear el track rellenado
        const pct = ((slider.value - slider.min) / (slider.max - slider.min)) * 100;
        slider.style.background = `linear-gradient(to right, var(--accent) ${pct}%, var(--surface-3) ${pct}%)`;
    }

    slider.addEventListener('input', updateDisplay);
    updateDisplay(); // Estado inicial
}

function getLength() {
    return parseInt(document.getElementById('length-slider').value, 10);
}

function setLength(val) {
    const slider  = document.getElementById('length-slider');
    const display = document.getElementById('length-value-display');
    const clamped = Math.max(parseInt(slider.min), Math.min(parseInt(slider.max), val));
    slider.value = clamped;
    display.textContent = clamped;
    const pct = ((clamped - slider.min) / (slider.max - slider.min)) * 100;
    slider.style.background = `linear-gradient(to right, var(--accent) ${pct}%, var(--surface-3) ${pct}%)`;
}


/* ─────────────────────────────────────────────────────────
   5. PALABRA CLAVE — Input sanitizado
   ───────────────────────────────────────────────────────── */

function initKeyword() {
    const useKw      = document.getElementById('use-keyword');
    const kwWrap     = document.getElementById('keyword-input-wrap');
    const kwInput    = document.getElementById('keyword-input');
    const kwHeader   = document.querySelector('.keyword-toggle-header');

    function updateVisibility() {
        if (useKw.checked) {
            kwWrap.classList.add('visible');
            kwHeader.classList.remove('keyword-closed-border');
        } else {
            kwWrap.classList.remove('visible');
            kwHeader.classList.add('keyword-closed-border');
        }
    }

    useKw.addEventListener('change', updateVisibility);

    // Sanitización en tiempo real: solo letras, sin espacios ni símbolos
    kwInput.addEventListener('input', () => {
        const raw     = kwInput.value;
        const cleaned = raw.replace(/[^a-zA-ZáéíóúÁÉÍÓÚñÑüÜ]/g, '');
        if (raw !== cleaned) kwInput.value = cleaned;
    });

    // Estado inicial
    updateVisibility();
}

/**
 * Convierte una palabra clave en una secuencia de caracteres
 * que "se asemeja" a ella pero incluye sustituciones leet, variaciones
 * de capitalización y caracteres del pool activo para reforzar fortaleza.
 * @param {string} keyword  — ya sanitizado
 * @param {boolean} useNumbers
 * @param {boolean} useSymbols
 * @returns {string}
 */
function buildKeywordBase(keyword, useNumbers, useSymbols) {
    if (!keyword) return '';

    // Sustituciones leet opcionales (se aplican aleatoriamente con p=0.5)
    const LEET_MAP = {
        'a': useNumbers ? '4' : 'A',
        'e': useNumbers ? '3' : 'E',
        'i': useNumbers ? '1' : 'I',
        'o': useNumbers ? '0' : 'O',
        's': useSymbols ? '$' : 'S',
        'at': useSymbols ? '@' : 'A',
    };

    let result = '';
    for (let i = 0; i < keyword.length; i++) {
        const ch  = keyword[i];
        const low = ch.toLowerCase();
        // Alternar mayúsculas de forma criptográficamente aleatoria
        const upperCase = secureRandIndex(2) === 1;
        // Aplicar leet con probabilidad 0.4
        const applyLeet = LEET_MAP[low] && secureRandIndex(10) < 4;
        if (applyLeet) {
            result += LEET_MAP[low];
        } else {
            result += upperCase ? ch.toUpperCase() : ch.toLowerCase();
        }
    }
    return result;
}


/* ─────────────────────────────────────────────────────────
   6. GENERADOR PRINCIPAL
   ───────────────────────────────────────────────────────── */

function generatePassword() {
    // Animación del botón
    const btn = document.getElementById('generate-btn');
    btn.classList.add('spinning');
    setTimeout(() => btn.classList.remove('spinning'), 600);

    // ── Leer opciones ────────────────────────────────────
    const useLetters   = document.getElementById('inc-letters').checked;
    const useNumbers   = document.getElementById('inc-numbers').checked;
    const useSymbols   = document.getElementById('inc-symbols').checked;
    const excludeSim   = document.getElementById('exc-similar').checked;
    const useKeyword   = document.getElementById('use-keyword').checked;
    const rawKeyword   = document.getElementById('keyword-input').value.trim();

    const rawLength    = getLength();

    // ── Validación básica de opciones ────────────────────
    if (!useLetters && !useNumbers && !useSymbols) {
        showToast("Selecciona al menos un tipo de carácter.", 'error');
        return;
    }

    // ── Similar chars set ────────────────────────────────
    const SIMILAR_SET = new Set(['0','O','o','1','l','I','|','2','Z','z','A','a','4','E','e','3']);

    function buildPool(chars) {
        if (!excludeSim) return chars;
        return chars.split('').filter(c => !SIMILAR_SET.has(c)).join('');
    }

    const poolLower   = buildPool('abcdefghijklmnopqrstuvwxyz');
    const poolUpper   = buildPool('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    const poolDigits  = buildPool('0123456789');
    const poolSymbols = '@$#*.%';  // Pool ampliado

    // ── Validar que los pools no queden vacíos ────────────
    if (useLetters && poolLower.length === 0 && poolUpper.length === 0) {
        showToast("Filtro de similares eliminó todas las letras.", 'error');
        return;
    }
    if (useNumbers && poolDigits.length === 0) {
        showToast("Filtro de similares eliminó todos los dígitos.", 'error');
        return;
    }

    // ── Pool completo ─────────────────────────────────────
    let fullPool = '';
    if (useLetters)  fullPool += poolLower + poolUpper;
    if (useNumbers)  fullPool += poolDigits;
    if (useSymbols)  fullPool += poolSymbols;

    // ── Construir componentes de la contraseña ────────────

    // 1. Prefijo de entidad
    const prefix = selectedPrefix;

    // 2. Base de palabra clave (si aplica)
    const kwBase = (useKeyword && rawKeyword.length > 0)
        ? buildKeywordBase(rawKeyword, useNumbers, useSymbols)
        : '';

    // 3. Garantizados (al menos 1 de cada tipo activo)
    const guaranteed = [];
    if (useLetters) {
        guaranteed.push(poolLower[secureRandIndex(poolLower.length)]);
        guaranteed.push(poolUpper[secureRandIndex(poolUpper.length)]);
    }
    if (useNumbers) {
        guaranteed.push(poolDigits[secureRandIndex(poolDigits.length)]);
    }
    if (useSymbols) {
        guaranteed.push(poolSymbols[secureRandIndex(poolSymbols.length)]);
    }

    // 4. Calcular relleno necesario
    const fixedLength     = prefix.length + kwBase.length + guaranteed.length;
    const mandatoryCount  = (useLetters ? 2 : 0) + (useNumbers ? 1 : 0) + (useSymbols ? 1 : 0);
    const minRequired     = prefix.length + (useKeyword && rawKeyword ? rawKeyword.length : 0) + mandatoryCount;
    const totalLength     = Math.max(minRequired, Math.min(64, rawLength));

    // Reflejar en slider si fue ajustado
    if (totalLength !== rawLength) setLength(totalLength);

    const fillerLen = Math.max(0, totalLength - fixedLength);
    const filler    = [];
    for (let i = 0; i < fillerLen; i++) {
        filler.push(fullPool[secureRandIndex(fullPool.length)]);
    }

    // 5. Mezclar solo la parte variable (guaranteed + filler), NO el prefijo ni la kw
    const variable  = secureShuffle([...guaranteed, ...filler]);
    const finalPwd  = prefix + kwBase + variable.join('');

    // ── Mostrar ───────────────────────────────────────────
    const pwdInput = document.getElementById('password-output');
    pwdInput.value = finalPwd;

    // Mantener visibilidad actual
    // (el input ya es type="password" por defecto, el toggle lo maneja)

    // ── Entropía ──────────────────────────────────────────
    updateEntropy(finalPwd, useLetters, useNumbers, useSymbols, excludeSim);

    // ── Autocopiado ───────────────────────────────────────
    if (document.getElementById('auto-copy').checked) {
        copyToClipboard(finalPwd, true);
    }
}


/* ─────────────────────────────────────────────────────────
   7. ENTROPÍA — Cálculo matemático de bits
   ─────────────────────────────────────────────────────────
   Fórmula: H = L × log₂(N)
     L = longitud de la contraseña
     N = tamaño del pool de caracteres posibles
   ───────────────────────────────────────────────────────── */

function calcEntropyBits(password, useLetters, useNumbers, useSymbols, excludeSimilar) {
    if (!password || password.length === 0) return 0;

    // Reconstruir pool para el cálculo (igual que en el generador)
    const SIMILAR_SET = new Set(['0','O','o','1','l','I','|','2','Z','z','A','a','4','E','e','3']);
    function poolSize(chars) {
        if (!excludeSimilar) return chars.length;
        return chars.split('').filter(c => !SIMILAR_SET.has(c)).length;
    }

    let N = 0;
    if (useLetters)  N += poolSize('abcdefghijklmnopqrstuvwxyz') + poolSize('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (useNumbers)  N += poolSize('0123456789');
    if (useSymbols)  N += '@$#*.%'.length;

    if (N <= 0) return 0;

    const L    = password.length;
    const bits = L * Math.log2(N);
    return Math.round(bits * 10) / 10; // 1 decimal
}

function getEntropyMeta(bits) {
    if (bits < 28)  return { label: 'Vulnerable',    color: 'var(--entr-low)',    pct: 8  };
    if (bits < 36)  return { label: 'Muy débil',     color: 'var(--entr-low)',    pct: 15 };
    if (bits < 48)  return { label: 'Débil',         color: 'var(--entr-fair)',   pct: 28 };
    if (bits < 60)  return { label: 'Razonable',     color: 'var(--entr-fair)',   pct: 42 };
    if (bits < 72)  return { label: 'Aceptable',     color: 'var(--entr-good)',   pct: 56 };
    if (bits < 90)  return { label: 'Fuerte',        color: 'var(--entr-strong)', pct: 70 };
    if (bits < 112) return { label: 'Muy fuerte',    color: 'var(--entr-strong)', pct: 84 };
    return               { label: '🔒 Inhackeable', color: 'var(--entr-max)',    pct: 100 };
}

function updateEntropy(password, useLetters, useNumbers, useSymbols, excludeSimilar) {
    const bits   = calcEntropyBits(password, useLetters, useNumbers, useSymbols, excludeSimilar);
    const meta   = getEntropyMeta(bits);

    const barFill   = document.getElementById('entropy-bar');
    const bitsEl    = document.getElementById('entropy-bits');
    const badgeEl   = document.getElementById('entropy-badge');

    barFill.style.width           = meta.pct + '%';
    barFill.style.backgroundColor = meta.color;
    bitsEl.textContent            = bits.toFixed(1) + ' bits';
    bitsEl.style.color            = meta.color;
    badgeEl.textContent           = meta.label;
    badgeEl.style.color           = meta.color;
    badgeEl.style.borderColor     = meta.color;
}


/* ─────────────────────────────────────────────────────────
   8. VISIBILIDAD — Mostrar / Ocultar contraseña
   ───────────────────────────────────────────────────────── */

function initVisibilityToggle() {
    const btn    = document.getElementById('toggle-visibility');
    const input  = document.getElementById('password-output');
    const eyeOpen   = btn.querySelector('.eye-open');
    const eyeClosed = btn.querySelector('.eye-closed');

    let visible = false;

    btn.addEventListener('click', () => {
        visible = !visible;
        input.type         = visible ? 'text' : 'password';
        eyeOpen.style.display   = visible ? 'none'  : 'block';
        eyeClosed.style.display = visible ? 'block' : 'none';
        btn.setAttribute('aria-label', visible ? 'Ocultar contraseña' : 'Mostrar contraseña');
    });
}


/* ─────────────────────────────────────────────────────────
   9. CLIPBOARD — Manual + Autocopiado
   ───────────────────────────────────────────────────────── */

let copyFeedbackTimer = null;

/**
 * Copia texto al portapapeles.
 * @param {string} text
 * @param {boolean} silent — si true, no selecciona el texto visualmente
 */
function copyToClipboard(text, silent = false) {
    if (!text) return;

    const pwdInput = document.getElementById('password-output');

    if (!silent) {
        pwdInput.select();
        pwdInput.setSelectionRange(0, 99999);
    }

    const doFeedback = () => {
        const copyBtn  = document.getElementById('copy-btn');
        const iconCopy  = copyBtn.querySelector('.icon-copy');
        const iconCheck = copyBtn.querySelector('.icon-check');

        iconCopy.style.display  = 'none';
        iconCheck.style.display = 'block';
        copyBtn.classList.add('copied');

        clearTimeout(copyFeedbackTimer);
        copyFeedbackTimer = setTimeout(() => {
            iconCopy.style.display  = 'block';
            iconCheck.style.display = 'none';
            copyBtn.classList.remove('copied');
        }, 2000);

        showToast(silent ? '⚡ Autocopiado al portapapeles' : '✓ Copiado al portapapeles', 'success');
    };

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
            .then(doFeedback)
            .catch(() => fallbackCopy(pwdInput, doFeedback));
    } else {
        fallbackCopy(pwdInput, doFeedback);
    }
}

function fallbackCopy(inputEl, onSuccess) {
    try {
        inputEl.select();
        inputEl.setSelectionRange(0, 99999);
        document.execCommand('copy');
        onSuccess();
    } catch {
        showToast('No se pudo copiar. Copia manualmente.', 'error');
    }
}

function initCopyButton() {
    const btn = document.getElementById('copy-btn');
    btn.addEventListener('click', () => {
        const val = document.getElementById('password-output').value;
        if (!val || val === '') {
            showToast('Genera una contraseña primero.', 'error');
            return;
        }
        copyToClipboard(val, false);
    });
}


/* ─────────────────────────────────────────────────────────
   10. TOAST — Sistema de notificaciones
   ───────────────────────────────────────────────────────── */

let toastTimer = null;

/**
 * Muestra un toast con mensaje y tipo.
 * @param {string} msg
 * @param {'success'|'error'|''} type
 */
function showToast(msg, type = '') {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.className   = 'toast show' + (type ? ' ' + type : '');

    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
        toast.classList.remove('show');
    }, 2800);
}


/* ─────────────────────────────────────────────────────────
   11. INIT — Inicialización de todos los módulos
   ───────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initEntitySelector();
    initSlider();
    initKeyword();
    initVisibilityToggle();
    initCopyButton();

    // Regenerar al cambiar cualquier opción (excepto autocopiado y tema)
    const triggers = [
        'inc-letters', 'inc-numbers', 'inc-symbols', 'exc-similar'
    ];
    triggers.forEach(id => {
        document.getElementById(id).addEventListener('change', generatePassword);
    });

    document.getElementById('length-slider').addEventListener('change', generatePassword);

    // Generar al cargar
    generatePassword();
});
