import { RequestSequence } from "./request_sequence.mjs";
import { initializeClaimedViewer, takeLauncherToken } from "./session.mjs";

(() => {
  "use strict";

  const pageSize = 100;
  const timelineLimit = 2000;
  const laneOrder = [
    "Browser",
    "Backend logs",
    "Kubernetes events",
    "Kubernetes pods",
    "Diagnostics",
  ];
  const state = {
    files: [],
    selectedFile: null,
    view: "timeline",
    filter: "all",
    query: "",
    offset: 0,
    hasMore: false,
    timeline: null,
    windowMinutes: "30",
    baseStart: null,
    baseEnd: null,
    viewportStart: null,
    viewportEnd: null,
    expandedLanes: new Set(),
    requestSequence: 0,
    detailRequests: new RequestSequence(),
    selectedMarker: null,
    accessToken: takeLauncherToken(),
    sessionClaimed: false,
    timelineController: null,
  };

  const elements = {
    browserCount: document.querySelector("#browser-count"),
    bundleStatus: document.querySelector("#bundle-status"),
    closeDialog: document.querySelector("#close-dialog"),
    dialogDetails: document.querySelector("#dialog-details"),
    dialogLane: document.querySelector("#dialog-lane"),
    dialogMeta: document.querySelector("#dialog-meta"),
    dialogSummary: document.querySelector("#dialog-summary"),
    fileCount: document.querySelector("#file-count"),
    fileList: document.querySelector("#file-list"),
    filesTab: document.querySelector("#files-tab"),
    filesView: document.querySelector("#files-view"),
    generatedAt: document.querySelector("#generated-at"),
    logCount: document.querySelector("#log-count"),
    nextPage: document.querySelector("#next-page"),
    notice: document.querySelector("#notice"),
    pageLabel: document.querySelector("#page-label"),
    previousPage: document.querySelector("#previous-page"),
    records: document.querySelector("#records"),
    recordTemplate: document.querySelector("#record-template"),
    retry: document.querySelector("#retry"),
    resultCount: document.querySelector("#result-count"),
    searchInput: document.querySelector("#search-input"),
    selectedCategory: document.querySelector("#selected-category"),
    selectedFile: document.querySelector("#selected-file"),
    timeline: document.querySelector("#timeline"),
    timelineCount: document.querySelector("#timeline-count"),
    timelineEarlier: document.querySelector("#timeline-earlier"),
    timelineLater: document.querySelector("#timeline-later"),
    timelineRange: document.querySelector("#timeline-range"),
    timelineReset: document.querySelector("#timeline-reset"),
    timelineTab: document.querySelector("#timeline-tab"),
    timelineView: document.querySelector("#timeline-view"),
    timelineZoomIn: document.querySelector("#timeline-zoom-in"),
    timelineZoomOut: document.querySelector("#timeline-zoom-out"),
    recordDialog: document.querySelector("#record-dialog"),
  };

  async function fetchJSON(path, parameters = null, options = {}) {
    const url = new URL(path, window.location.origin);
    if (parameters) {
      Object.entries(parameters).forEach(([key, value]) => {
        if (value !== "" && value !== null && value !== undefined) {
          url.searchParams.set(key, String(value));
        }
      });
    }
    const response = await fetch(url, {
      credentials: "same-origin",
      signal: options.signal,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${state.accessToken}`,
      },
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json();
  }

  async function initialize() {
    const [manifest, filesResponse] = await Promise.all([
      fetchJSON("/api/manifest"),
      fetchJSON("/api/files"),
    ]);
    updateSummary(manifest);
    state.files = filesResponse.files || [];
    renderFiles();
    const defaultFile =
      state.files.find((file) => file.path === "browser/network.jsonl") ||
      state.files[0];
    if (defaultFile) {
      selectFile(defaultFile, false);
    }
    await loadTimeline(true);
  }

  function updateSummary(manifest) {
    const collection = manifest.collection || {};
    const browser = collection.browser || {};
    const browserStats = browser.stats || {};
    const kubernetes = collection.kubernetes || {};
    const status = collection.status || "Unknown";
    elements.bundleStatus.textContent = status;
    elements.bundleStatus.className =
      `status-${String(status).toLowerCase().replace(/[^a-z0-9_-]/g, "-")}`;
    elements.browserCount.textContent = formatNumber(browserStats.entries_written);
    elements.logCount.textContent = formatNumber(kubernetes.log_files);
    elements.generatedAt.textContent = formatTimestamp(manifest.generated_at);
  }

  function renderFiles() {
    elements.fileList.replaceChildren();
    elements.fileCount.textContent = `${state.files.length} files`;
    let currentCategory = "";
    state.files.forEach((file) => {
      if (file.category !== currentCategory) {
        currentCategory = file.category;
        const heading = document.createElement("div");
        heading.className = "file-category";
        heading.textContent = currentCategory;
        elements.fileList.append(heading);
      }
      const button = document.createElement("button");
      button.type = "button";
      button.className = "file-button";
      button.dataset.path = file.path;
      button.title = `${file.path} · ${formatBytes(file.size)}`;
      button.textContent = displayFileName(file.path);
      button.addEventListener("click", () => selectFile(file));
      elements.fileList.append(button);
    });
  }

  function selectFile(file, load = true) {
    state.selectedFile = file;
    state.offset = 0;
    document.querySelectorAll(".file-button").forEach((button) => {
      button.classList.toggle("active", button.dataset.path === file.path);
    });
    elements.selectedCategory.textContent = file.category;
    elements.selectedFile.textContent = file.path;
    if (load && state.view === "files") {
      loadRecords();
    }
  }

  async function loadTimeline(initializing = false) {
    const sequence = ++state.requestSequence;
    state.timelineController?.abort();
    const controller = new AbortController();
    state.timelineController = controller;
    elements.timeline.replaceChildren(createTimelineEmpty("Building correlated timeline…"));
    hideNotice();
    try {
      const response = await fetchJSON("/api/timeline", {
        query: state.query,
        filter: state.filter,
        limit: timelineLimit,
      }, {
        signal: controller.signal,
      });
      if (sequence !== state.requestSequence) {
        return;
      }
      state.timeline = response;
      resetTimelineViewport();
      renderTimeline();
    } catch (error) {
      if (error.name === "AbortError") {
        return;
      }
      if (initializing) {
        throw error;
      }
      if (sequence !== state.requestSequence) {
        return;
      }
      elements.timeline.replaceChildren();
      showNotice(`Could not build timeline: ${error.message}`);
    } finally {
      if (state.timelineController === controller) {
        state.timelineController = null;
      }
    }
  }

  function renderTimeline() {
    if (!state.timeline) {
      return;
    }
    const allRecords = state.timeline.records || [];
    const windowRecords = recordsInWindow(allRecords, state.windowMinutes);
    if (windowRecords.length === 0) {
      elements.timelineCount.textContent = "0 visible events";
      elements.timelineRange.textContent = "No timestamped records";
      elements.timeline.replaceChildren(
        createTimelineEmpty("No timestamped events match this filter."),
      );
      return;
    }
    const windowTimestamps = windowRecords.map(
      (record) => new Date(record.timestamp).getTime(),
    );
    state.baseStart = Math.min(...windowTimestamps);
    state.baseEnd = Math.max(...windowTimestamps);
    if (state.baseStart === state.baseEnd) {
      state.baseStart -= 1000;
      state.baseEnd += 1000;
    }
    if (
      state.viewportStart === null ||
      state.viewportEnd === null ||
      state.viewportStart < state.baseStart ||
      state.viewportEnd > state.baseEnd
    ) {
      state.viewportStart = state.baseStart;
      state.viewportEnd = state.baseEnd;
    }
    const start = state.viewportStart;
    const end = state.viewportEnd;
    const records = windowRecords.filter((record) => {
      const timestamp = new Date(record.timestamp).getTime();
      return timestamp >= start && timestamp <= end;
    });
    elements.timelineCount.textContent =
      `${records.length.toLocaleString()} of ${windowRecords.length.toLocaleString()} window events`;
    elements.timelineRange.textContent =
      `${formatTimelineTimestamp(start)} — ${formatTimelineTimestamp(end)}`;
    updateTimelineControls();

    const inner = document.createElement("div");
    inner.className = "timeline-inner";
    inner.append(createRuler(start, end));

    const recordsByLane = new Map();
    records.forEach((record) => {
      if (!recordsByLane.has(record.lane)) {
        recordsByLane.set(record.lane, []);
      }
      recordsByLane.get(record.lane).push(record);
    });
    laneOrder.forEach((lane) => {
      const laneRecords = recordsByLane.get(lane);
      if (laneRecords?.length) {
        inner.append(createLane(lane, laneRecords, start, end));
      }
    });
    if (records.length === 0) {
      inner.append(createTimelineEmpty("No events in this zoomed interval."));
    }

    const caption = document.createElement("div");
    caption.className = "timeline-caption";
    const coverage = document.createElement("span");
    const total = state.timeline.total_matches || 0;
    coverage.textContent =
      state.timeline.truncated && total > allRecords.length
        ? `Showing the latest ${allRecords.length.toLocaleString()} of ${total.toLocaleString()} matching events`
        : `${total.toLocaleString()} matching events`;
    const instruction = document.createElement("span");
    instruction.textContent = "Select a marker to inspect the full record";
    caption.append(coverage, instruction);
    inner.append(caption);
    elements.timeline.replaceChildren(inner);
  }

  function createRuler(start, end) {
    const row = document.createElement("div");
    row.className = "ruler-row";
    const title = document.createElement("div");
    title.className = "ruler-title";
    title.textContent = "Systems";
    const track = document.createElement("div");
    track.className = "ruler-track";
    for (let index = 0; index <= 4; index += 1) {
      const position = index * 25;
      const tick = document.createElement("div");
      tick.className = "ruler-tick";
      tick.style.left = `${position}%`;
      const label = document.createElement("span");
      label.textContent = formatRulerTime(start + ((end - start) * position) / 100);
      tick.append(label);
      track.append(tick);
    }
    row.append(title, track);
    return row;
  }

  function createLane(lane, records, start, end) {
    const fragment = document.createDocumentFragment();
    const groups = new Map();
    records.forEach((record) => {
      const group = record.group || "Other";
      if (!groups.has(group)) {
        groups.set(group, []);
      }
      groups.get(group).push(record);
    });
    const expandable = groups.size > 1;
    fragment.append(
      createLaneRow(lane, records, start, end, {
        lane,
        expandable,
        sublane: false,
      }),
    );
    if (expandable && state.expandedLanes.has(lane)) {
      [...groups.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .forEach(([group, groupRecords]) => {
          fragment.append(
            createLaneRow(group, groupRecords, start, end, {
              lane,
              expandable: false,
              sublane: true,
            }),
          );
        });
    }
    return fragment;
  }

  function createLaneRow(labelValue, records, start, end, options) {
    const row = document.createElement("div");
    row.className = `lane-row${options.sublane ? " sublane" : ""}`;
    const label = document.createElement(options.expandable ? "button" : "div");
    label.className = "lane-label";
    if (options.expandable) {
      label.type = "button";
      label.classList.add("expandable");
      const expanded = state.expandedLanes.has(options.lane);
      label.setAttribute("aria-expanded", String(expanded));
      label.addEventListener("click", () => {
        if (expanded) {
          state.expandedLanes.delete(options.lane);
        } else {
          state.expandedLanes.add(options.lane);
        }
        renderTimeline();
      });
    }
    const icon = document.createElement("span");
    icon.className = "lane-icon";
    icon.textContent = options.sublane
      ? "·"
      : options.expandable
        ? state.expandedLanes.has(options.lane)
          ? "▾"
          : "▸"
        : laneInitials(options.lane);
    const labelText = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = labelValue;
    const count = document.createElement("small");
    const clusterThreshold = options.sublane ? 180 : 350;
    const clustered = records.length > clusterThreshold;
    count.textContent =
      `${records.length.toLocaleString()} visible${clustered ? " · clustered" : ""}`;
    labelText.append(name, count);
    label.append(icon, labelText);

    const track = document.createElement("div");
    track.className = "lane-track";
    if (clustered) {
      createClusters(records, start, end).forEach((cluster) => {
        track.append(createClusterMarker(labelValue, cluster, start, end));
      });
      row.append(label, track);
      return row;
    }
    const rowLastPosition = [-Infinity, -Infinity, -Infinity, -Infinity, -Infinity];
    records.forEach((record) => {
      const timestamp = new Date(record.timestamp).getTime();
      const position = ((timestamp - start) / (end - start)) * 100;
      let stack = rowLastPosition.findIndex(
        (lastPosition) => position-lastPosition >= 1.25,
      );
      if (stack === -1) {
        stack = rowLastPosition.indexOf(Math.min(...rowLastPosition));
      }
      rowLastPosition[stack] = position;
      track.append(createMarker(record, position, stack, end - start));
    });
    row.append(label, track);
    return row;
  }

  function createClusters(records, start, end) {
    const binCount = 120;
    const bins = Array.from({ length: binCount }, () => []);
    records.forEach((record) => {
      const timestamp = new Date(record.timestamp).getTime();
      const ratio = Math.max(0, Math.min(0.999999, (timestamp - start) / (end - start)));
      bins[Math.floor(ratio * binCount)].push(record);
    });
    return bins.filter((recordsInBin) => recordsInBin.length > 0);
  }

  function createClusterMarker(lane, records, start, end) {
    const firstTime = new Date(records[0].timestamp).getTime();
    const lastTime = new Date(records.at(-1).timestamp).getTime();
    const midpoint = firstTime + (lastTime - firstTime) / 2;
    const position = ((midpoint - start) / (end - start)) * 100;
    const marker = document.createElement("button");
    marker.type = "button";
    marker.className = `event-marker cluster ${highestSeverity(records)}`;
    marker.style.left = `${Math.max(0.15, Math.min(99.85, position))}%`;
    marker.style.height = `${Math.min(72, 12 + Math.log2(records.length) * 8)}px`;
    if (records.length >= 10) {
      marker.textContent = String(records.length);
    }
    marker.title =
      `${records.length} events · ${formatTimestamp(records[0].timestamp)} — ` +
      formatTimestamp(records.at(-1).timestamp);
    marker.setAttribute("aria-label", marker.title);
    marker.addEventListener("click", () => openClusterDetails(lane, records, marker));
    return marker;
  }

  function highestSeverity(records) {
    if (records.some((record) => record.severity === "error")) {
      return "error";
    }
    if (records.some((record) => record.severity === "warning")) {
      return "warning";
    }
    return "info";
  }

  function createMarker(record, position, stack, rangeMilliseconds) {
    const marker = document.createElement("button");
    marker.type = "button";
    marker.className = `event-marker ${record.severity || "info"} ${record.kind || ""}`;
    marker.style.left = `${Math.max(0.15, Math.min(99.85, position))}%`;
    marker.style.top = `${10 + stack * 16}px`;
    if (record.duration_ms > 0 && rangeMilliseconds > 0) {
      const durationPercent = (record.duration_ms / rangeMilliseconds) * 100;
      marker.style.width = `${Math.min(8, Math.max(0.15, durationPercent))}%`;
    }
    const label =
      `${formatTimestamp(record.timestamp)} · ${record.summary || "Record"}`;
    marker.title = label;
    marker.setAttribute("aria-label", label);
    marker.addEventListener("click", () => openRecordDetails(record, marker));
    return marker;
  }

  function recordsInWindow(records, windowMinutes) {
    if (windowMinutes === "all" || records.length === 0) {
      return records;
    }
    const latest = Math.max(
      ...records.map((record) => new Date(record.timestamp).getTime()),
    );
    const cutoff = latest - Number(windowMinutes) * 60 * 1000;
    return records.filter(
      (record) => new Date(record.timestamp).getTime() >= cutoff,
    );
  }

  async function openRecordDetails(record, marker) {
    const request = state.detailRequests.next();
    selectMarker(marker);
    elements.dialogLane.textContent = record.lane || "Event";
    elements.dialogSummary.textContent = record.summary || "Record details";
    elements.dialogMeta.replaceChildren(
      createMetaChip(formatTimestamp(record.timestamp)),
      createMetaChip(record.severity || "info"),
      createMetaChip(record.path),
      createMetaChip(`line ${record.line}`),
    );
    elements.dialogDetails.textContent = "Loading full record…";
    if (!elements.recordDialog.open) {
      elements.recordDialog.showModal();
    }
    try {
      const details = await fetchJSON("/api/record", {
        path: record.path,
        line: record.line,
      });
      if (
        !state.detailRequests.isCurrent(request) ||
        state.selectedMarker !== marker ||
        !elements.recordDialog.open
      ) {
        return;
      }
      elements.dialogDetails.textContent =
        typeof details.details === "string"
          ? details.details
          : JSON.stringify(details.details, null, 2);
    } catch (error) {
      if (
        !state.detailRequests.isCurrent(request) ||
        state.selectedMarker !== marker ||
        !elements.recordDialog.open
      ) {
        return;
      }
      elements.dialogDetails.textContent = `Could not load record: ${error.message}`;
    }
  }

  function openClusterDetails(lane, records, marker) {
    state.detailRequests.invalidate();
    selectMarker(marker);
    elements.dialogLane.textContent = lane;
    elements.dialogSummary.textContent = `${records.length.toLocaleString()} events in this time slice`;
    elements.dialogMeta.replaceChildren(
      createMetaChip(formatTimestamp(records[0].timestamp)),
      createMetaChip(formatTimestamp(records.at(-1).timestamp)),
      createMetaChip(highestSeverity(records)),
    );
    const visibleRecords = records.slice(-200);
    const lines = visibleRecords.map(
      (record) =>
        `${formatTimestamp(record.timestamp)}  ${record.severity.toUpperCase().padEnd(7)}  ${record.summary}`,
    );
    if (records.length > visibleRecords.length) {
      lines.unshift(
        `[${(records.length - visibleRecords.length).toLocaleString()} earlier events omitted; narrow the time window or use File explorer]`,
      );
    }
    elements.dialogDetails.textContent = lines.join("\n");
    if (!elements.recordDialog.open) {
      elements.recordDialog.showModal();
    }
  }

  function selectMarker(marker) {
    state.selectedMarker?.classList.remove("selected");
    state.selectedMarker = marker;
    marker.classList.add("selected");
  }

  function createMetaChip(text) {
    const chip = document.createElement("span");
    chip.textContent = text;
    return chip;
  }

  async function loadRecords() {
    if (!state.selectedFile) {
      return;
    }
    const sequence = ++state.requestSequence;
    elements.records.replaceChildren(createEmpty("Loading records…"));
    hideNotice();
    try {
      const response = await fetchJSON("/api/records", {
        path: state.selectedFile.path,
        query: state.query,
        filter: state.filter,
        offset: state.offset,
        limit: pageSize,
      });
      if (sequence !== state.requestSequence) {
        return;
      }
      state.hasMore = response.has_more;
      renderRecords(response.records || []);
      updatePagination();
    } catch (error) {
      if (sequence !== state.requestSequence) {
        return;
      }
      elements.records.replaceChildren();
      showNotice(`Could not read records: ${error.message}`);
    }
  }

  function renderRecords(records) {
    elements.records.replaceChildren();
    elements.resultCount.textContent = `${records.length} shown`;
    if (records.length === 0) {
      elements.records.append(createEmpty("No records match this filter."));
      return;
    }
    const fragment = document.createDocumentFragment();
    records.forEach((record) => {
      const node = elements.recordTemplate.content.cloneNode(true);
      const article = node.querySelector(".record");
      article.classList.add(record.severity || "info");
      node.querySelector("time").textContent = formatTimestamp(record.timestamp);
      node.querySelector(".source").textContent = record.source || "unknown";
      node.querySelector(".severity").textContent = record.severity || "info";
      node.querySelector(".line").textContent = `line ${record.line}`;
      node.querySelector(".record-summary").textContent = record.summary || "—";
      node.querySelector("pre").textContent =
        typeof record.details === "string"
          ? record.details
          : JSON.stringify(record.details, null, 2);
      fragment.append(node);
    });
    elements.records.append(fragment);
  }

  function updatePagination() {
    const page = Math.floor(state.offset / pageSize) + 1;
    elements.pageLabel.textContent = `Page ${page}`;
    elements.previousPage.disabled = state.offset === 0;
    elements.nextPage.disabled = !state.hasMore;
  }

  function showNotice(message, retry = false) {
    elements.notice.textContent = message;
    if (retry) {
      elements.notice.append(" ", elements.retry);
      elements.retry.classList.remove("hidden");
    }
    elements.notice.classList.remove("hidden");
  }

  function hideNotice() {
    elements.notice.classList.add("hidden");
    elements.notice.textContent = "";
    elements.retry.classList.add("hidden");
  }

  function createEmpty(message) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = message;
    return empty;
  }

  function createTimelineEmpty(message) {
    const empty = document.createElement("div");
    empty.className = "timeline-empty";
    empty.textContent = message;
    return empty;
  }

  function laneInitials(lane) {
    switch (lane) {
      case "Browser":
        return "BR";
      case "Backend logs":
        return "BE";
      case "Kubernetes events":
        return "KE";
      case "Kubernetes pods":
        return "KP";
      default:
        return "DX";
    }
  }

  function displayFileName(path) {
    const parts = path.split("/");
    if (path.startsWith("kubernetes/logs/") && parts.length >= 4) {
      return `${parts.at(-2)} / ${parts.at(-1)}`;
    }
    return parts.at(-1);
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) {
      return "—";
    }
    if (bytes < 1024) {
      return `${bytes} B`;
    }
    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(1)} KiB`;
    }
    return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  }

  function formatNumber(value) {
    return Number.isFinite(value) ? value.toLocaleString() : "—";
  }

  function formatTimestamp(value) {
    if (!value) {
      return "No timestamp";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  }

  function formatTimelineTimestamp(value) {
    const date = new Date(value);
    return date.toLocaleString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function formatRulerTime(value) {
    const date = new Date(value);
    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function resetTimelineViewport() {
    state.baseStart = null;
    state.baseEnd = null;
    state.viewportStart = null;
    state.viewportEnd = null;
  }

  function zoomTimeline(scale) {
    if (
      state.baseStart === null ||
      state.baseEnd === null ||
      state.viewportStart === null ||
      state.viewportEnd === null
    ) {
      return;
    }
    const availableDuration = state.baseEnd - state.baseStart;
    const currentDuration = state.viewportEnd - state.viewportStart;
    const nextDuration = Math.max(
      1000,
      Math.min(availableDuration, currentDuration * scale),
    );
    const center = state.viewportStart + currentDuration / 2;
    let nextStart = center - nextDuration / 2;
    let nextEnd = center + nextDuration / 2;
    if (nextStart < state.baseStart) {
      nextStart = state.baseStart;
      nextEnd = nextStart + nextDuration;
    }
    if (nextEnd > state.baseEnd) {
      nextEnd = state.baseEnd;
      nextStart = nextEnd - nextDuration;
    }
    state.viewportStart = nextStart;
    state.viewportEnd = nextEnd;
    renderTimeline();
  }

  function panTimeline(direction) {
    if (
      state.baseStart === null ||
      state.baseEnd === null ||
      state.viewportStart === null ||
      state.viewportEnd === null
    ) {
      return;
    }
    const duration = state.viewportEnd - state.viewportStart;
    const shift = duration * 0.45 * direction;
    let nextStart = state.viewportStart + shift;
    let nextEnd = state.viewportEnd + shift;
    if (nextStart < state.baseStart) {
      nextStart = state.baseStart;
      nextEnd = nextStart + duration;
    }
    if (nextEnd > state.baseEnd) {
      nextEnd = state.baseEnd;
      nextStart = nextEnd - duration;
    }
    state.viewportStart = nextStart;
    state.viewportEnd = nextEnd;
    renderTimeline();
  }

  function updateTimelineControls() {
    const duration = state.viewportEnd - state.viewportStart;
    const availableDuration = state.baseEnd - state.baseStart;
    elements.timelineZoomIn.disabled = duration <= 1000;
    elements.timelineZoomOut.disabled = duration >= availableDuration;
    elements.timelineEarlier.disabled = state.viewportStart <= state.baseStart;
    elements.timelineLater.disabled = state.viewportEnd >= state.baseEnd;
    elements.timelineReset.disabled =
      state.viewportStart === state.baseStart && state.viewportEnd === state.baseEnd;
  }

  function switchView(view) {
    state.view = view;
    const timelineActive = view === "timeline";
    elements.timelineView.classList.toggle("hidden", !timelineActive);
    elements.filesView.classList.toggle("hidden", timelineActive);
    elements.timelineTab.classList.toggle("active", timelineActive);
    elements.filesTab.classList.toggle("active", !timelineActive);
    elements.timelineTab.setAttribute("aria-selected", String(timelineActive));
    elements.filesTab.setAttribute("aria-selected", String(!timelineActive));
    if (!timelineActive && state.selectedFile) {
      loadRecords();
    } else if (timelineActive && !state.timeline) {
      loadTimeline();
    }
  }

  let searchTimer;
  elements.searchInput.addEventListener("input", (event) => {
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => {
      state.query = event.target.value;
      state.offset = 0;
      if (state.view === "timeline") {
        loadTimeline();
      } else {
        loadRecords();
      }
    }, 250);
  });

  document.querySelectorAll(".filter").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".filter").forEach((candidate) => {
        candidate.classList.toggle("active", candidate === button);
      });
      state.filter = button.dataset.filter;
      state.offset = 0;
      if (state.view === "timeline") {
        loadTimeline();
      } else {
        loadRecords();
      }
    });
  });

  document.querySelectorAll(".window").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".window").forEach((candidate) => {
        candidate.classList.toggle("active", candidate === button);
      });
      state.windowMinutes = button.dataset.window;
      resetTimelineViewport();
      renderTimeline();
    });
  });

  elements.timelineTab.addEventListener("click", () => switchView("timeline"));
  elements.filesTab.addEventListener("click", () => switchView("files"));
  elements.timelineZoomIn.addEventListener("click", () => zoomTimeline(0.5));
  elements.timelineZoomOut.addEventListener("click", () => zoomTimeline(2));
  elements.timelineEarlier.addEventListener("click", () => panTimeline(-1));
  elements.timelineLater.addEventListener("click", () => panTimeline(1));
  elements.timelineReset.addEventListener("click", () => {
    resetTimelineViewport();
    renderTimeline();
  });

  elements.previousPage.addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - pageSize);
    loadRecords();
  });
  elements.nextPage.addEventListener("click", () => {
    if (state.hasMore) {
      state.offset += pageSize;
      loadRecords();
    }
  });

  elements.closeDialog.addEventListener("click", () => {
    elements.recordDialog.close();
  });
  elements.recordDialog.addEventListener("close", () => {
    state.detailRequests.invalidate();
    state.selectedMarker?.classList.remove("selected");
    state.selectedMarker = null;
  });

  async function openViewer() {
    if (!state.accessToken) {
      showNotice("Open this viewer through the launcher file printed by the server.");
      return;
    }
    try {
      await initializeClaimedViewer(state, initialize);
    } catch (error) {
      showNotice(
        error.status === 409
          ? "This viewer session is already open in another tab. Restart the viewer to open a new session."
          : `Could not open the bundle: ${error.message}`,
        error.status !== 409,
      );
    }
  }

  elements.retry.addEventListener("click", () => {
    elements.retry.disabled = true;
    void openViewer().finally(() => {
      elements.retry.disabled = false;
    });
  });

  void openViewer();
})();
