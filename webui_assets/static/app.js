"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const CSRF_TOKEN = csrfMeta ? (csrfMeta.getAttribute("content") || "") : "";

  const state = {
    tab: "all",
    search: "",
    offset: 0,
    limit: 50,
    total: 0,
    configLoaded: false,
    filesTick: 0,
    filesReqId: 0,
  };

  const PHASE_LABELS = {
    idle: "Готов к работе",
    preflight: "Проверка доступа и квоты…",
    indexing: "Читаю список Безлимита…",
    scanning: "Сканирую папку на ПК…",
    uploading: "Загружаю фото и видео…",
    watching: "Наблюдаю за папкой…",
    done: "Завершено",
    error: "Требуется внимание",
  };

  const STATUS_LABELS = {
    pending: "В очереди",
    uploading: "Загружается",
    uploaded: "Загружен",
    skipped_remote: "Уже в Безлимите",
    skipped_dup_local: "Дубль в папке",
    skipped_limit: "Превышен лимит размера",
    skipped_unsupported: "Пропущен",
    failed: "Ошибка",
  };

  const ALLOWED_EVENT_KINDS = new Set(["info", "ok", "warn", "err", "run"]);

  function fmtBytes(n) {
    if (!n || n <= 0) return "0 Б";
    const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let v = Number(n);
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    return (i === 0 ? Math.round(v) : v < 100 ? v.toFixed(1) : Math.round(v)) + " " + units[i];
  }

  function fmtNum(n) {
    return Number(n || 0).toLocaleString("ru-RU");
  }

  function showAlert(kind, text) {
    const el = $("global-alert");
    if (!text) {
      el.className = "banner hidden";
      el.textContent = "";
      return;
    }
    el.className = "banner " + (kind === "err" ? "banner-err" : kind === "ok" ? "banner-ok" : "banner-warn");
    el.textContent = text;
  }

  async function api(url, opts) {
    const init = Object.assign({}, opts || {});
    const headers = Object.assign({}, init.headers || {});
    const method = String(init.method || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD") {
      headers["X-CSRF-Token"] = CSRF_TOKEN;
      headers["X-Requested-With"] = "XMLHttpRequest";
    }
    init.headers = headers;

    const r = await fetch(url, init);
    let body = null;
    try {
      body = await r.json();
    } catch (_e) {
      body = null;
    }
    if (!r.ok) {
      const msg = (body && body.detail) ? body.detail : ("Ошибка запроса (HTTP " + r.status + ")");
      throw new Error(msg);
    }
    return body;
  }

  async function withBusy(btn, fn) {
    if (!btn || btn.disabled) return;
    btn.disabled = true;
    try {
      await fn();
    } finally {
      btn.disabled = false;
    }
  }

  function renderActiveFiles(running, active) {
    const activeBox = $("active-files");
    if (!running || active.length === 0) {
      activeBox.classList.add("hidden");
      activeBox.replaceChildren();
      return;
    }
    activeBox.classList.remove("hidden");
    const nodes = active.map((a) => {
      const p = a.total > 0 ? Math.min(100, Math.round((a.sent * 100) / a.total)) : 0;
      const stg = a.stage === "hashing"
        ? "контрольная сумма"
        : (p + "% · " + fmtBytes(a.sent) + " / " + fmtBytes(a.total));
      const row = document.createElement("div");
      row.className = "active-item";
      const left = document.createElement("span");
      left.textContent = String(a.name || "");
      const right = document.createElement("span");
      right.textContent = stg;
      row.append(left, right);
      return row;
    });
    activeBox.replaceChildren(...nodes);
  }

  function renderEvents(events) {
    const evList = $("events-list");
    if (events.length === 0) {
      const li = document.createElement("li");
      li.className = "ev-empty";
      li.textContent = "События появятся после начала проверки или загрузки.";
      evList.replaceChildren(li);
      return;
    }
    const nodes = events.map((ev) => {
      const kind = ALLOWED_EVENT_KINDS.has(ev.kind) ? ev.kind : "info";
      const li = document.createElement("li");
      li.className = "ev-" + kind;
      const timeSpan = document.createElement("span");
      timeSpan.className = "ev-time";
      timeSpan.textContent = String(ev.at || "");
      const textSpan = document.createElement("span");
      textSpan.textContent = String(ev.text || "");
      li.append(timeSpan, textSpan);
      return li;
    });
    evList.replaceChildren(...nodes);
  }

  function renderStatus(data) {
    const running = Boolean(data.running);
    const live = data.live || {};
    const stats = data.stats || {};
    const ck = data.cookies || {};
    const acc = data.account || null;
    const cfg = data.config || {};

    if (!state.configLoaded) {
      $("source-dir").value = cfg.source_dir || "";
      $("set-workers").value = cfg.max_workers || 2;
      $("set-chunk").value = cfg.chunk_mb || 16;
      $("set-strict-guard").checked = cfg.strict_quota_guard !== false;
      $("set-watch").checked = Boolean(cfg.watch_mode);
      state.configLoaded = true;
    }

    const phase = live.phase || (running ? "uploading" : "idle");
    const phaseLabel = Object.hasOwn(PHASE_LABELS, phase) ? PHASE_LABELS[phase] : String(phase);
    const pill = $("status-pill");
    pill.textContent = phaseLabel;
    pill.className = "pill " + (running ? "pill-run" : phase === "error" ? "pill-err" : phase === "done" ? "pill-ok" : "");

    const cBadge = $("cookies-badge");
    if (ck.ok) {
      cBadge.textContent = "Подключено";
      cBadge.className = "badge badge-ok";
      $("btn-del-cookies").classList.remove("hidden");
    } else if (ck.present) {
      cBadge.textContent = "Нужно обновить";
      cBadge.className = "badge badge-err";
      $("btn-del-cookies").classList.remove("hidden");
    } else {
      cBadge.textContent = "Не настроен";
      cBadge.className = "badge";
      $("btn-del-cookies").classList.add("hidden");
    }

    const accBox = $("account-box");
    const qWarn = $("quota-warning");
    const ovRow = $("overdraft-confirm-row");
    if (acc) {
      accBox.classList.remove("hidden");
      $("acc-used").textContent = fmtBytes(acc.used) + " из " + fmtBytes(acc.limit);
      $("acc-unlim").textContent = fmtBytes(acc.actual_photounlim_size);
      $("acc-limit").textContent = fmtBytes(acc.filesize_limit);
      $("acc-guard").textContent = acc.unlimited_free ? "Безлимит активен" : "Нет активной подписки 360";
      if (acc.warning) {
        qWarn.textContent = acc.warning;
        qWarn.classList.remove("hidden");
        ovRow.classList.remove("hidden");
      } else {
        qWarn.classList.add("hidden");
        ovRow.classList.add("hidden");
        $("allow-quota-count").checked = false;
      }
    } else {
      accBox.classList.add("hidden");
      qWarn.classList.add("hidden");
      ovRow.classList.add("hidden");
      $("allow-quota-count").checked = false;
    }

    $("btn-scan").disabled = running;
    $("btn-start").disabled = running;
    $("btn-pick-folder").disabled = running;
    $("btn-save-cookies").disabled = running;
    $("btn-del-cookies").disabled = running;
    $("btn-reset-queue").disabled = running;
    $("btn-stop").classList.toggle("hidden", !running);
    $("btn-start").classList.toggle("hidden", running);
    $("btn-retry").classList.toggle("hidden", running || !(stats.failed > 0));

    const totalMedia = stats.media_files || 0;
    const processed = (stats.uploaded || 0) + (stats.skipped_remote || 0) + (stats.skipped_dup_local || 0);
    const pct = totalMedia > 0 ? Math.min(100, Math.round((processed * 100) / totalMedia)) : 0;
    $("progress-fill").style.width = pct + "%";
    $("progress-pct").textContent = pct + "%";
    $("progress-text").textContent = data.message || (
      totalMedia > 0
        ? "Обработано " + fmtNum(processed) + " из " + fmtNum(totalMedia) + " медиафайлов"
        : "Выберите папку и нажмите «Проверить папку» или «Загрузить в Безлимит»"
    );

    let phaseLine = phaseLabel;
    if (phase === "indexing" && live.indexed_remote) {
      phaseLine += " (" + fmtNum(live.indexed_remote) + ")";
    } else if (phase === "scanning" && live.scanned_files) {
      phaseLine += " (" + fmtNum(live.scanned_files) + ")";
    } else if (live.cooldown_sec > 0) {
      phaseLine = "Пауза по запросу Яндекса: " + live.cooldown_sec + " с";
    }
    $("live-phase").textContent = phaseLine;
    $("live-speed").textContent = live.speed_bps > 0 ? (fmtBytes(live.speed_bps) + "/с") : "";

    renderActiveFiles(running, live.active_files || []);

    $("st-photos").textContent = fmtNum(stats.photos);
    $("st-photos-b").textContent = fmtBytes(stats.photos_bytes);
    $("st-videos").textContent = fmtNum(stats.videos);
    $("st-videos-b").textContent = fmtBytes(stats.videos_bytes);
    $("st-uploaded").textContent = fmtNum(stats.uploaded);
    $("st-uploaded-b").textContent = fmtBytes(stats.uploaded_bytes);
    $("st-pending").textContent = fmtNum((stats.pending || 0) + (stats.uploading || 0));
    $("st-pending-b").textContent = fmtBytes((stats.pending_bytes || 0) + (stats.uploading_bytes || 0));
    $("st-dups").textContent = fmtNum((stats.skipped_remote || 0) + (stats.skipped_dup_local || 0));
    $("st-issues").textContent = fmtNum(stats.skipped_unsupported) + " / " + fmtNum(stats.failed);
    $("remote-count-note").textContent = stats.remote_index_count
      ? ("В Безлимите учтено: " + fmtNum(stats.remote_index_count))
      : "";

    renderEvents(data.events || []);
  }

  async function loadFiles() {
    const reqId = ++state.filesReqId;
    const q = new URLSearchParams({
      status: state.tab,
      search: state.search,
      offset: String(state.offset),
      limit: String(state.limit),
    });
    $("btn-export-csv").href = "/api/export.csv?status=" + encodeURIComponent(state.tab);
    try {
      const res = await api("/api/files?" + q.toString());
      if (reqId !== state.filesReqId) return;
      state.total = res.total || 0;
      if (state.total > 0 && state.offset >= state.total) {
        state.offset = Math.floor((state.total - 1) / state.limit) * state.limit;
        await loadFiles();
        return;
      }
      const tbody = $("files-tbody");
      if (!res.items || res.items.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 3;
        td.className = "td-empty";
        td.textContent = "Нет файлов по выбранному фильтру.";
        tr.append(td);
        tbody.replaceChildren(tr);
      } else {
        const rows = res.items.map((it) => {
          const stKey = String(it.status || "");
          const stLabel = Object.hasOwn(STATUS_LABELS, stKey) ? STATUS_LABELS[stKey] : stKey;
          const tr = document.createElement("tr");

          const tdPath = document.createElement("td");
          tdPath.textContent = String(it.rel_path || "");
          if (it.error) {
            const sub = document.createElement("span");
            sub.className = "file-sub";
            sub.textContent = String(it.error);
            tdPath.append(sub);
          }

          const tdSize = document.createElement("td");
          tdSize.textContent = fmtBytes(it.size);

          const tdStatus = document.createElement("td");
          tdStatus.textContent = stLabel;

          tr.append(tdPath, tdSize, tdStatus);
          return tr;
        });
        tbody.replaceChildren(...rows);
      }
      const from = state.total === 0 ? 0 : state.offset + 1;
      const to = Math.min(state.total, state.offset + state.limit);
      $("pager-info").textContent = fmtNum(from) + "–" + fmtNum(to) + " из " + fmtNum(state.total);
      $("btn-prev-page").disabled = state.offset <= 0;
      $("btn-next-page").disabled = (state.offset + state.limit) >= state.total;
    } catch (_e) {
      // не шумим при временном обновлении таблицы
    }
  }

  async function pollOnce() {
    try {
      const data = await api("/api/status");
      renderStatus(data);
      state.filesTick += 1;
      if (state.filesTick % 3 === 1) {
        await loadFiles();
      }
    } catch (_e) {
      // сервер мог перезагружаться
    }
  }

  async function pollLoop() {
    await pollOnce();
    setTimeout(pollLoop, 1500);
  }

  function bindEvents() {
    $("btn-save-cookies").addEventListener("click", () => withBusy($("btn-save-cookies"), async () => {
      const text = $("cookies-input").value.trim();
      if (!text) {
        showAlert("warn", "Вставьте скопированные куки из браузера.");
        return;
      }
      showAlert("info", "Проверяю данные входа в Яндексе…");
      try {
        const res = await api("/api/cookies", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text }),
        });
        $("cookies-input").value = "";
        showAlert("ok", res.warning || "Данные входа сохранены и подтверждены.");
        await pollOnce();
      } catch (e) {
        showAlert("err", e.message);
      }
    }));

    $("btn-check-cookies").addEventListener("click", () => withBusy($("btn-check-cookies"), async () => {
      showAlert("info", "Проверяю доступ к Яндекс.Диску…");
      try {
        await api("/api/cookies/check", { method: "POST" });
        showAlert("ok", "Доступ к Яндекс.Диску работает.");
        await pollOnce();
      } catch (e) {
        showAlert("err", e.message);
      }
    }));

    $("btn-del-cookies").addEventListener("click", () => withBusy($("btn-del-cookies"), async () => {
      if (!confirm("Удалить сохранённые данные входа (cookies.json)?")) return;
      try {
        await api("/api/cookies", { method: "DELETE" });
        showAlert("ok", "Данные входа удалены.");
        await pollOnce();
      } catch (e) {
        showAlert("err", e.message);
      }
    }));

    $("btn-pick-folder").addEventListener("click", () => withBusy($("btn-pick-folder"), async () => {
      try {
        const res = await api("/api/folder/pick", { method: "POST" });
        if (res.picked && res.path) {
          $("source-dir").value = res.path;
          showAlert("ok", "Выбрана папка: " + res.path);
        }
      } catch (e) {
        showAlert("err", e.message);
      }
    }));

    $("btn-save-settings").addEventListener("click", () => withBusy($("btn-save-settings"), async () => {
      try {
        await api("/api/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            source_dir: $("source-dir").value.trim(),
            max_workers: Number($("set-workers").value),
            chunk_mb: Number($("set-chunk").value),
            strict_quota_guard: $("set-strict-guard").checked,
            watch_mode: $("set-watch").checked,
          }),
        });
        showAlert("ok", "Настройки сохранены.");
      } catch (e) {
        showAlert("err", e.message);
      }
    }));

    $("btn-scan").addEventListener("click", () => withBusy($("btn-scan"), async () => {
      showAlert("", "");
      try {
        await api("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ source_dir: $("source-dir").value.trim() }),
        });
        await pollOnce();
      } catch (e) {
        showAlert("err", e.message);
      }
    }));

    $("btn-start").addEventListener("click", () => withBusy($("btn-start"), async () => {
      showAlert("", "");
      try {
        await api("/api/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            source_dir: $("source-dir").value.trim(),
            allow_quota_count: $("allow-quota-count").checked,
            watch_mode: $("set-watch").checked,
          }),
        });
        await pollOnce();
      } catch (e) {
        showAlert("err", e.message);
      }
    }));

    $("btn-stop").addEventListener("click", () => withBusy($("btn-stop"), async () => {
      try {
        await api("/api/stop", { method: "POST" });
        await pollOnce();
      } catch (e) {
        showAlert("err", e.message);
      }
    }));

    $("btn-retry").addEventListener("click", () => withBusy($("btn-retry"), async () => {
      try {
        const res = await api("/api/retry-failed", { method: "POST" });
        showAlert("ok", "Возвращено в очередь: " + res.requeued + ". Нажмите «Загрузить в Безлимит».");
        await pollOnce();
        await loadFiles();
      } catch (e) {
        showAlert("err", e.message);
      }
    }));

    $("btn-reset-queue").addEventListener("click", () => withBusy($("btn-reset-queue"), async () => {
      if (!confirm("Очистить локальный список очереди? Файлы на компьютере и в Яндекс.Диске не пострадают.")) return;
      try {
        await api("/api/reset", { method: "POST" });
        state.offset = 0;
        showAlert("ok", "Очередь очищена.");
        await pollOnce();
        await loadFiles();
      } catch (e) {
        showAlert("err", e.message);
      }
    }));

    $("file-tabs").addEventListener("click", (ev) => {
      const btn = ev.target.closest(".tab");
      if (!btn) return;
      document.querySelectorAll("#file-tabs .tab").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.tab = btn.dataset.status || "all";
      state.offset = 0;
      loadFiles();
    });

    let searchTimer = null;
    $("file-search").addEventListener("input", () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        state.search = $("file-search").value.trim();
        state.offset = 0;
        loadFiles();
      }, 250);
    });

    $("btn-prev-page").addEventListener("click", () => {
      state.offset = Math.max(0, state.offset - state.limit);
      loadFiles();
    });
    $("btn-next-page").addEventListener("click", () => {
      if (state.offset + state.limit < state.total) {
        state.offset += state.limit;
        loadFiles();
      }
    });
  }

  bindEvents();
  pollLoop();
})();
