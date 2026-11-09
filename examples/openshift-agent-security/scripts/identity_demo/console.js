/* SPDX-License-Identifier: Apache-2.0 */
(() => {
  'use strict';
  const main = document.querySelector('main[data-live-url]');
  let clockOffset = 0;
  const updateSessionClock = () => {
    const now = (Date.now() + clockOffset) / 1000;
    document.querySelectorAll('[data-session-deadline]').forEach(el => {
      const seconds = Math.max(0, Math.ceil(Number(el.dataset.sessionDeadline) - now));
      el.textContent = seconds ? Math.floor(seconds / 60) + 'm ' + seconds % 60 + 's remaining' : 'Sign in again';
      const state = el.closest('.account-session')?.querySelector('[data-session-state]');
      if (state) {
        state.classList.toggle('expired', !seconds);
        state.querySelector('[data-session-state-label]').textContent = seconds ? 'Active' : 'Sign-in needed';
      }
    });
  };
  const setSessionDeadline = deadline => {
    if (!Number.isSafeInteger(deadline) || deadline <= 0) return;
    document.querySelectorAll('[data-session-deadline]').forEach(el => { el.dataset.sessionDeadline = deadline; });
    updateSessionClock();
  };
  updateSessionClock();
  setInterval(updateSessionClock, 1000);
  if (!main) return;
  const notice = document.getElementById('connection-status');
  const seenResponses = new Set();
  let lastProgress = null;
  let revision = '', failures = 0, stopped = false, latestHome = null, lastReadiness = '';
  const setNotice = message => {
    notice.textContent = message;
    notice.hidden = !message;
    main.dataset.connection = message ? 'unavailable' : 'connected';
  };
  const freeze = () => main.querySelectorAll('form button').forEach(b => { b.disabled = true; });
  function patch(html) {
    const root = document.getElementById('live-content');
    const opened = new Set([...root.querySelectorAll('details[open]')].map(d => d.querySelector('summary')?.textContent));
    const focused = document.activeElement;
    const focusForm = focused?.closest('form')?.getAttribute('action');
    const focusText = focused?.tagName === 'BUTTON' ? focused.textContent : null;
    const focusSummary = focused?.tagName === 'SUMMARY' ? focused.textContent : null;
    const selectedNode = root.querySelector('[data-node][aria-pressed="true"]')?.dataset.node;
    const railScroll = root.querySelector('.progress-sticky')?.scrollLeft || 0;
    const scroll = [window.scrollX, window.scrollY];
    root.innerHTML = html;
    const rail = root.querySelector('.progress-sticky');
    if (rail) rail.scrollLeft = railScroll;
    if (selectedNode) inspect(selectedNode);
    updateMotion();
    showResponses();
    alignProgress();
    root.querySelectorAll('details').forEach(d => { d.open = opened.has(d.querySelector('summary')?.textContent); });
    if (focusForm && focusText) {
      const b = [...root.querySelectorAll('form button')].find(b => b.closest('form').getAttribute('action') === focusForm && b.textContent === focusText);
      b?.focus({preventScroll:true});
    } else if (focused?.dataset.node) {
      [...root.querySelectorAll('[data-node]')].find(b => b.dataset.node === focused.dataset.node)?.focus({preventScroll:true});
    } else if (focusSummary) {
      [...root.querySelectorAll('summary')].find(s => s.textContent === focusSummary)?.focus({preventScroll:true});
    }
    window.scrollTo(...scroll);
  }
  function showResponses() {
    main.querySelectorAll('[data-response-event]').forEach(path => {
      const key = path.dataset.responseEvent;
      if (seenResponses.has(key)) return;
      seenResponses.add(key);
      if (path.dataset.responseRecent === 'true' && main.dataset.connection !== 'unavailable') path.classList.add('arriving');
    });
  }
  function alignProgress(force = false) {
    const rail = main.querySelector('.progress-sticky');
    const step = rail?.querySelector('[aria-current="step"]');
    if (!step || (!force && lastProgress === step.dataset.step)) return;
    lastProgress = step.dataset.step;
    if (rail.scrollWidth > rail.clientWidth) {
      const box = step.getBoundingClientRect(), container = rail.getBoundingClientRect();
      rail.scrollLeft += box.left-container.left-(rail.clientWidth-box.width)/2;
    }
  }
  window.addEventListener('resize', () => alignProgress(true));
  function inspect(node) {
    main.querySelectorAll('[data-node]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.node === node)));
    main.querySelectorAll('[data-inspector]').forEach(p => { p.hidden = p.dataset.inspector !== node; });
    main.querySelectorAll('.inspector-placeholder').forEach(p => { p.hidden = true; });
  }
  function updateMotion() {
    const paused = document.documentElement.dataset.motion === 'paused';
    main.querySelectorAll('[data-motion-toggle]').forEach(b => {
      b.setAttribute('aria-pressed', String(paused)); b.textContent = paused ? 'Resume motion' : 'Pause motion';
    });
  }
  main.addEventListener('click', event => {
    const node = event.target.closest('[data-node]');
    if (node) inspect(node.dataset.node);
    if (event.target.closest('[data-motion-toggle]')) {
      document.documentElement.dataset.motion = document.documentElement.dataset.motion === 'paused' ? 'playing' : 'paused';
      updateMotion();
    }
  });
  function cvePreview() {
    const select = main.querySelector('select[name="role"]');
    main.querySelectorAll('[data-cve-preview]').forEach(el => {
      el.hidden = !select || el.dataset.cvePreview !== select.value;
    });
  }
  function home(data) {
    latestHome = data;
    main.querySelectorAll('[data-readiness-status]').forEach(el => {el.textContent=data.coordinator_label;});
    main.querySelectorAll('[data-active-count]').forEach(el => {el.textContent=data.active_runs;});
    main.querySelectorAll('[data-retained-count]').forEach(el => {el.textContent=data.retained_runs+' (latest 50)';});
    const panel = document.getElementById('readiness-panel');
    if (panel && lastReadiness !== data.readiness_html) { panel.innerHTML = data.readiness_html; lastReadiness = data.readiness_html; }
    const select = main.querySelector('select[name="role"]');
    // Leave the native popup untouched while the user is choosing. Even an
    // identical textContent assignment can close it on a polling update.
    if (select && document.activeElement !== select) [...select.options].forEach(o => {
      const available = data.cve_roles.includes(o.value), label = o.dataset.label || o.textContent;
      const nextLabel = available ? label : label + ' · fresh context needed';
      if (o.disabled !== !available) o.disabled = !available;
      if (o.textContent !== nextLabel) o.textContent = nextLabel;
    });
    main.querySelectorAll('form[action="/submit"]').forEach(form => {
      const cve = !!form.querySelector('[name="cve"]');
      const incident = form.dataset.workflow === 'incident-triage';
      const available = cve ? !!select && data.cve_roles.includes(select.value) : incident ? data.incident_available : data.service_available;
      form.querySelector('button').disabled = !data.can_start || !available;
      const hint = document.getElementById(cve ? 'cve-availability' : incident ? 'incident-availability' : 'service-availability');
      if (hint) hint.textContent = available ? 'Prepared context available.' : data.missing_context_hint;
    });
  }
  async function poll() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(main.dataset.liveUrl, {credentials:'same-origin',cache:'no-store',redirect:'error',signal:controller.signal,headers:{Accept:'application/json', ...(revision ? {'If-None-Match': '"'+revision+'"'} : {})}});
      if (response.status === 401 || response.status === 403) {
        freeze();
        setNotice('Your sign-in has expired or access is unavailable. Use Sign in again to continue. An existing run keeps its original deadline.');
        const link = document.createElement('a'); link.href = '/login'; link.textContent = ' Sign in again'; notice.append(link);
        stopped = true; return;
      }
      if (response.status === 304) {
        setSessionDeadline(Number(response.headers.get('X-Session-Deadline')));
        failures=0; setNotice(''); return;
      }
      if (!response.ok) throw new Error('status unavailable');
      const data = await response.json();
      clockOffset = data.server_time * 1000 - Date.now();
      setSessionDeadline(data.session_deadline);
      failures = 0; setNotice('');
      if (main.dataset.liveKind === 'home') home(data);
      else {
        if (data.revision !== revision) { patch(data.html); revision = data.revision; }
        if (!data.poll) stopped = true;
      }
      document.querySelectorAll('[data-connection-label]').forEach(el => { el.textContent = data.poll === false ? 'Final recorded state' : 'Live updates connected'; });
    } catch (_) {
      failures++;
      setNotice('Reconnecting to live updates. The last recorded state remains below. Do not submit the same action again.');
    } finally {
      clearTimeout(timeout);
      if (!stopped) setTimeout(poll, Math.min(15000, 2500 * Math.max(1, failures)));
    }
  }
  // Enter confirms a workload selection; starting a run requires activating
  // its explicit button. The server still authorizes every actual submission.
  main.addEventListener('keydown', event => {
    if (event.key === 'Enter' && event.target.matches('select')) event.preventDefault();
  });
  main.addEventListener('focusout', event => {
    if (event.target.matches('select') && latestHome) setTimeout(() => home(latestHome), 0);
  });
  document.addEventListener('submit', event => {
    const form = event.target;
    if (form.dataset.submitting) { event.preventDefault(); return; }
    form.dataset.submitting = 'true';
    setTimeout(() => {
      if (event.defaultPrevented) { delete form.dataset.submitting; return; }
      form.querySelectorAll('button').forEach(b => { b.disabled = true; });
    }, 0);
  });
  main.addEventListener('change', () => { cvePreview(); if (latestHome) home(latestHome); });
  setInterval(() => {
    const now = (Date.now() + clockOffset) / 1000;
    main.querySelectorAll('[data-elapsed-since]').forEach(el => {
      const seconds = Math.max(0, Math.floor(now - Number(el.dataset.elapsedSince)));
      el.textContent = seconds >= 60 ? Math.floor(seconds / 60) + 'm ' + seconds % 60 + 's' : seconds + 's';
    });
    main.querySelectorAll('[data-deadline]').forEach(el => {
      const seconds = Math.max(0, Math.ceil(Number(el.dataset.deadline) - now));
      el.textContent = seconds ? Math.floor(seconds / 60) + 'm ' + seconds % 60 + 's remaining' : 'Expired';
    });
  }, 1000);
  cvePreview();
  alignProgress();
  poll();
})();
