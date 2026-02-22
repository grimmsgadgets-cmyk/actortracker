      (function () {
        const actorId = document.body.dataset.actorId || "";
        if (!actorId) return;

        const liveIndicator = document.getElementById("live-indicator");
        const liveRefresh = document.getElementById("live-refresh");
        const reportNode = document.getElementById("recent-reports");
        const targetsNode = document.getElementById("recent-targets");
        const impactNode = document.getElementById("recent-impact");

        async function fetchLiveState() {
          const response = await fetch("/actors/" + encodeURIComponent(actorId) + "/ui/live", { headers: { "Accept": "application/json" } });
          if (!response.ok) return null;
          return response.json();
        }

        function applyLiveState(data) {
          if (!data) return;
          if (liveIndicator) {
            const state = String(data.notebook_status || "idle");
            liveIndicator.textContent = "Live: " + state;
          }
          const recent = data.recent_change_summary || {};
          if (reportNode && recent.new_reports !== undefined) reportNode.textContent = String(recent.new_reports);
          if (targetsNode && recent.targets !== undefined) targetsNode.textContent = String(recent.targets);
          if (impactNode && recent.damage !== undefined) impactNode.textContent = String(recent.damage);
        }

        async function runLiveRefresh() {
          try {
            const data = await fetchLiveState();
            applyLiveState(data);
          } catch (error) {
            if (liveIndicator) liveIndicator.textContent = "Live sync unavailable";
          }
        }

        if (liveRefresh) liveRefresh.addEventListener("click", runLiveRefresh);
        setInterval(runLiveRefresh, 20000);
        runLiveRefresh();

        const severitySelect = document.getElementById("timeline-severity");
        const categorySelect = document.getElementById("timeline-category");
        const searchInput = document.getElementById("timeline-search");
        const timelineRows = Array.from(document.querySelectorAll("#timeline-filter-body tr"));
        const timelineEmpty = document.getElementById("timeline-empty");
        const timelineReset = document.getElementById("timeline-reset");
        const timelineFilterChips = document.getElementById("timeline-filter-chips");
        const observationCards = Array.from(document.querySelectorAll("[data-observation-item-type][data-observation-item-key]"));
        const observationLedgerList = document.getElementById("observation-ledger-list");
        const observationLedgerEmpty = document.getElementById("observation-ledger-empty");
        const observationLedgerCount = document.getElementById("observation-ledger-count");
        const ledgerFilterChips = document.getElementById("ledger-filter-chips");
        const ledgerFilterAnalyst = document.getElementById("ledger-filter-analyst");
        const ledgerFilterConfidence = document.getElementById("ledger-filter-confidence");
        const ledgerFilterFrom = document.getElementById("ledger-filter-from");
        const ledgerFilterTo = document.getElementById("ledger-filter-to");
        const ledgerLimit = document.getElementById("ledger-limit");
        const ledgerApply = document.getElementById("ledger-apply");
        const ledgerClear = document.getElementById("ledger-clear");
        const ledgerExportJson = document.getElementById("ledger-export-json");
        const ledgerExportCsv = document.getElementById("ledger-export-csv");
        const cmdkOverlay = document.getElementById("cmdk-overlay");
        const cmdkInput = document.getElementById("cmdk-input");
        const cmdkList = document.getElementById("cmdk-list");
        const sinceReviewDate = document.getElementById("since-review-date");
        const sinceReviewObservations = document.getElementById("since-review-observations");
        const sinceReviewSources = document.getElementById("since-review-sources");
        const sinceReviewReports = document.getElementById("since-review-reports");
        const markReviewed = document.getElementById("mark-reviewed");
        const clearReviewed = document.getElementById("clear-reviewed");
        const reviewMeta = document.getElementById("review-meta");
        const sourceDateNodes = Array.from(document.querySelectorAll(".recent-source-list li[data-source-date]"));
        const reviewStorageKey = "tracker:lastReview:" + actorId;

        function applyTimelineFilter() {
          const severity = (severitySelect && severitySelect.value || "").toLowerCase();
          const category = (categorySelect && categorySelect.value || "").toLowerCase();
          const query = (searchInput && searchInput.value || "").trim().toLowerCase();
          let visibleCount = 0;
          timelineRows.forEach((row) => {
            const rowSeverity = (row.dataset.severity || "").toLowerCase();
            const rowCategory = (row.dataset.category || "").toLowerCase();
            const rowSearch = (row.dataset.search || "").toLowerCase();
            const matchesSeverity = !severity || rowSeverity === severity;
            const matchesCategory = !category || rowCategory === category;
            const matchesQuery = !query || rowSearch.includes(query);
            const visible = matchesSeverity && matchesCategory && matchesQuery;
            row.style.display = visible ? "" : "none";
            if (visible) visibleCount += 1;
          });
          if (timelineEmpty) timelineEmpty.style.display = visibleCount === 0 ? "" : "none";
          renderTimelineChips();
        }

        function addChip(container, label, onRemove) {
          if (!container) return;
          const chip = document.createElement("span");
          chip.className = "filter-chip";
          chip.textContent = label + " ";
          const button = document.createElement("button");
          button.type = "button";
          button.textContent = "x";
          button.addEventListener("click", onRemove);
          chip.appendChild(button);
          container.appendChild(chip);
        }

        function renderTimelineChips() {
          if (!timelineFilterChips) return;
          timelineFilterChips.innerHTML = "";
          const severity = (severitySelect && severitySelect.value || "").trim();
          const category = (categorySelect && categorySelect.value || "").trim();
          const query = (searchInput && searchInput.value || "").trim();
          if (severity) addChip(timelineFilterChips, "Severity: " + severity, () => { if (severitySelect) severitySelect.value = ""; applyTimelineFilter(); });
          if (category) addChip(timelineFilterChips, "Category: " + category, () => { if (categorySelect) categorySelect.value = ""; applyTimelineFilter(); });
          if (query) addChip(timelineFilterChips, "Text: " + query, () => { if (searchInput) searchInput.value = ""; applyTimelineFilter(); });
        }

        [severitySelect, categorySelect, searchInput].forEach((element) => {
          if (!element) return;
          element.addEventListener("input", applyTimelineFilter);
          element.addEventListener("change", applyTimelineFilter);
        });
        if (timelineReset) {
          timelineReset.addEventListener("click", () => {
            if (severitySelect) severitySelect.value = "";
            if (categorySelect) categorySelect.value = "";
            if (searchInput) searchInput.value = "";
            applyTimelineFilter();
          });
        }

        const observationStore = new Map();
        function observationMapKey(itemType, itemKey) {
          return String(itemType || "") + "::" + String(itemKey || "");
        }

        function ratingLabel(item) {
          const sr = String(item.source_reliability || "").trim();
          const ic = String(item.information_credibility || "").trim();
          return (sr || ic) ? sr + ic : "n/a";
        }

        function ledgerFilters() {
          return {
            analyst: String((ledgerFilterAnalyst && ledgerFilterAnalyst.value) || "").trim().toLowerCase(),
            confidence: String((ledgerFilterConfidence && ledgerFilterConfidence.value) || "").trim().toLowerCase(),
            updated_from: String((ledgerFilterFrom && ledgerFilterFrom.value) || "").trim(),
            updated_to: String((ledgerFilterTo && ledgerFilterTo.value) || "").trim(),
            limit: Math.max(1, parseInt(String((ledgerLimit && ledgerLimit.value) || "12"), 10) || 12)
          };
        }

        function buildQueryString(filters) {
          const params = new URLSearchParams();
          if (filters.analyst) params.set("analyst", filters.analyst);
          if (filters.confidence) params.set("confidence", filters.confidence);
          if (filters.updated_from) params.set("updated_from", filters.updated_from);
          if (filters.updated_to) params.set("updated_to", filters.updated_to);
          const query = params.toString();
          return query ? "?" + query : "";
        }

        function updateLedgerExportLinks(filters) {
          const query = buildQueryString(filters);
          if (ledgerExportJson) ledgerExportJson.href = "/actors/" + encodeURIComponent(actorId) + "/observations/export.json" + query;
          if (ledgerExportCsv) ledgerExportCsv.href = "/actors/" + encodeURIComponent(actorId) + "/observations/export.csv" + query;
        }

        function renderLedgerChips(filters) {
          if (!ledgerFilterChips) return;
          ledgerFilterChips.innerHTML = "";
          if (filters.analyst) addChip(ledgerFilterChips, "Analyst: " + filters.analyst, () => { if (ledgerFilterAnalyst) ledgerFilterAnalyst.value = ""; renderObservationLedger(); });
          if (filters.confidence) addChip(ledgerFilterChips, "Confidence: " + filters.confidence, () => { if (ledgerFilterConfidence) ledgerFilterConfidence.value = ""; renderObservationLedger(); });
          if (filters.updated_from) addChip(ledgerFilterChips, "From: " + filters.updated_from, () => { if (ledgerFilterFrom) ledgerFilterFrom.value = ""; renderObservationLedger(); });
          if (filters.updated_to) addChip(ledgerFilterChips, "To: " + filters.updated_to, () => { if (ledgerFilterTo) ledgerFilterTo.value = ""; renderObservationLedger(); });
        }

        function applyObservationCard(card) {
          const itemType = card.dataset.observationItemType || "";
          const itemKey = card.dataset.observationItemKey || "";
          const data = observationStore.get(observationMapKey(itemType, itemKey)) || {};
          const analystField = card.querySelector(".observation-analyst");
          const confidenceField = card.querySelector(".observation-confidence");
          const sourceReliabilityField = card.querySelector(".observation-source-reliability");
          const infoCredibilityField = card.querySelector(".observation-information-credibility");
          const sourceRefField = card.querySelector(".observation-source-ref");
          const noteField = card.querySelector(".observation-note");
          const metaNode = card.querySelector("[data-observation-meta]");
          const guidanceNode = card.querySelector("[data-observation-guidance]");

          if (analystField && data.updated_by) analystField.value = data.updated_by;
          if (confidenceField && data.confidence) confidenceField.value = data.confidence;
          if (sourceReliabilityField && data.source_reliability !== undefined) sourceReliabilityField.value = data.source_reliability;
          if (infoCredibilityField && data.information_credibility !== undefined) infoCredibilityField.value = data.information_credibility;
          if (sourceRefField && data.source_ref) sourceRefField.value = data.source_ref;
          if (noteField && data.note) noteField.value = data.note;
          if (metaNode) {
            const updatedAt = String(data.updated_at || "");
            const updatedBy = String(data.updated_by || "");
            const confidence = String(data.confidence || "moderate");
            const ratingText = ratingLabel(data);
            metaNode.textContent = updatedAt ? "Saved " + updatedAt + " by " + (updatedBy || "analyst") + " | " + confidence + " | rating " + ratingText : "";
          }
          if (guidanceNode) {
            const guidanceItems = Array.isArray(data.quality_guidance) ? data.quality_guidance : [];
            guidanceNode.textContent = guidanceItems.length ? "Guidance: " + guidanceItems.join(" ") : "";
          }
        }

        function renderObservationLedger() {
          if (!observationLedgerList || !observationLedgerEmpty) return;
          observationLedgerList.innerHTML = "";
          const filters = ledgerFilters();
          updateLedgerExportLinks(filters);
          renderLedgerChips(filters);
          const items = Array.from(observationStore.values())
            .filter((item) => {
              const by = String(item.updated_by || "").toLowerCase();
              const conf = String(item.confidence || "").toLowerCase();
              const updated = String(item.updated_at || "").slice(0, 10);
              if (filters.analyst && !by.includes(filters.analyst)) return false;
              if (filters.confidence && conf !== filters.confidence) return false;
              if (filters.updated_from && updated && updated < filters.updated_from) return false;
              if (filters.updated_to && updated && updated > filters.updated_to) return false;
              return true;
            })
            .sort((a, b) => String(b.updated_at || "").localeCompare(String(a.updated_at || "")));
          if (!items.length) {
            observationLedgerEmpty.style.display = "";
            if (observationLedgerCount) observationLedgerCount.textContent = "0 shown";
            return;
          }
          observationLedgerEmpty.style.display = "none";
          const limited = items.slice(0, filters.limit);
          if (observationLedgerCount) observationLedgerCount.textContent = String(limited.length) + " shown";
          limited.forEach((item) => {
            const wrap = document.createElement("div");
            wrap.className = "ledger-item";
            const head = document.createElement("div");
            head.className = "ledger-head";
            const by = document.createElement("span");
            by.textContent = "By " + String(item.updated_by || "analyst");
            const at = document.createElement("span");
            at.textContent = String(item.updated_at || "");
            const conf = document.createElement("span");
            conf.textContent = "Confidence: " + String(item.confidence || "moderate");
            const rating = document.createElement("span");
            rating.textContent = "Rating: " + ratingLabel(item);
            head.append(by, at, conf, rating);
            const body = document.createElement("div");
            body.className = "ledger-body";
            body.textContent = String(item.note || "(no note text)");
            wrap.append(head, body);
            const sourceTitle = String(item.source_title || item.source_name || "");
            const sourceUrl = String(item.source_url || "");
            if (sourceTitle || sourceUrl) {
              const linkWrap = document.createElement("div");
              linkWrap.className = "ledger-link";
              const sourceText = document.createElement(sourceUrl ? "a" : "span");
              if (sourceUrl) {
                sourceText.href = sourceUrl;
                sourceText.target = "_blank";
                sourceText.rel = "noreferrer";
              }
              sourceText.textContent = sourceTitle || sourceUrl;
              linkWrap.appendChild(sourceText);
              wrap.appendChild(linkWrap);
            }
            observationLedgerList.appendChild(wrap);
          });
          renderSinceReview();
        }

        function parseIsoDate(value) {
          const raw = String(value || "").trim();
          if (!raw) return null;
          const normalized = raw.replace("Z", "+00:00");
          const dt = new Date(normalized);
          if (!Number.isNaN(dt.getTime())) return dt;
          if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
            const dt2 = new Date(raw + "T00:00:00Z");
            return Number.isNaN(dt2.getTime()) ? null : dt2;
          }
          return null;
        }

        function sourceDateCandidates() {
          return sourceDateNodes
            .map((node) => {
              const attr = String(node.getAttribute("data-source-date") || "").trim();
              const badge = node.querySelector(".badge");
              const badgeText = badge ? String(badge.textContent || "").trim() : "";
              return attr || badgeText;
            })
            .filter((v) => v);
        }

        function renderSinceReview() {
          const baselineRaw = localStorage.getItem(reviewStorageKey) || "";
          const baseline = parseIsoDate(baselineRaw);
          if (!baseline) {
            if (sinceReviewDate) sinceReviewDate.textContent = "Not set";
            if (sinceReviewObservations) sinceReviewObservations.textContent = "0";
            if (sinceReviewSources) sinceReviewSources.textContent = "0";
            if (sinceReviewReports && reportNode) sinceReviewReports.textContent = String(reportNode.textContent || "0");
            if (reviewMeta) reviewMeta.textContent = "Set a baseline date to track changes between review cycles.";
            return;
          }
          if (sinceReviewDate) sinceReviewDate.textContent = baseline.toISOString().slice(0, 10);
          const obsCount = Array.from(observationStore.values()).filter((item) => {
            const dt = parseIsoDate(item.updated_at);
            return dt && dt >= baseline;
          }).length;
          if (sinceReviewObservations) sinceReviewObservations.textContent = String(obsCount);
          const sourceCount = sourceDateCandidates().filter((value) => {
            const dt = parseIsoDate(value);
            return dt && dt >= baseline;
          }).length;
          if (sinceReviewSources) sinceReviewSources.textContent = String(sourceCount);
          if (sinceReviewReports && reportNode) sinceReviewReports.textContent = String(reportNode.textContent || "0");
          if (reviewMeta) reviewMeta.textContent = "Baseline stored locally for this actor on this browser.";
        }

        if (markReviewed) {
          markReviewed.addEventListener("click", () => {
            localStorage.setItem(reviewStorageKey, new Date().toISOString());
            renderSinceReview();
          });
        }
        if (clearReviewed) {
          clearReviewed.addEventListener("click", () => {
            localStorage.removeItem(reviewStorageKey);
            renderSinceReview();
          });
        }

        function scrollToStep(selector) {
          const node = document.querySelector(selector);
          if (!node) return;
          node.scrollIntoView({ behavior: "smooth", block: "start" });
        }

        const commandActions = [
          { label: "Go to Who section", run: () => scrollToStep("#section-who") },
          { label: "Go to Recent section", run: () => scrollToStep("#section-recent") },
          { label: "Go to Interpretation section", run: () => scrollToStep("#section-history") },
          { label: "Go to Timeline section", run: () => scrollToStep("#section-timeline") },
          { label: "Refresh live now", run: () => runLiveRefresh() },
          { label: "Open timeline details", run: () => window.open("/actors/" + encodeURIComponent(actorId) + "/timeline/details", "_blank", "noopener,noreferrer") },
          { label: "Export observations CSV", run: () => window.open("/actors/" + encodeURIComponent(actorId) + "/observations/export.csv", "_blank", "noopener,noreferrer") },
          { label: "Export observations JSON", run: () => window.open("/actors/" + encodeURIComponent(actorId) + "/observations/export.json", "_blank", "noopener,noreferrer") },
        ];
        let commandCursor = 0;
        let visibleCommands = commandActions.slice();

        function renderCommandPalette() {
          if (!cmdkList || !cmdkInput) return;
          const query = String(cmdkInput.value || "").trim().toLowerCase();
          visibleCommands = commandActions.filter((item) => item.label.toLowerCase().includes(query));
          if (!visibleCommands.length) {
            cmdkList.innerHTML = '<div class="cmdk-empty">No matching actions.</div>';
            commandCursor = 0;
            return;
          }
          if (commandCursor >= visibleCommands.length) commandCursor = 0;
          cmdkList.innerHTML = "";
          visibleCommands.forEach((item, idx) => {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "cmdk-item" + (idx === commandCursor ? " active" : "");
            button.textContent = item.label;
            button.addEventListener("click", () => {
              closeCommandPalette();
              item.run();
            });
            cmdkList.appendChild(button);
          });
        }

        function openCommandPalette() {
          if (!cmdkOverlay || !cmdkInput) return;
          cmdkOverlay.classList.add("open");
          cmdkOverlay.setAttribute("aria-hidden", "false");
          cmdkInput.value = "";
          commandCursor = 0;
          renderCommandPalette();
          cmdkInput.focus();
        }

        function closeCommandPalette() {
          if (!cmdkOverlay) return;
          cmdkOverlay.classList.remove("open");
          cmdkOverlay.setAttribute("aria-hidden", "true");
        }

        document.addEventListener("keydown", (event) => {
          const isCommandK = (event.key.toLowerCase() === "k") && (event.metaKey || event.ctrlKey);
          if (isCommandK) {
            event.preventDefault();
            if (cmdkOverlay && cmdkOverlay.classList.contains("open")) closeCommandPalette();
            else openCommandPalette();
            return;
          }
          if (!cmdkOverlay || !cmdkOverlay.classList.contains("open")) return;
          if (event.key === "Escape") {
            event.preventDefault();
            closeCommandPalette();
            return;
          }
          if (event.key === "ArrowDown") {
            event.preventDefault();
            commandCursor = Math.min(commandCursor + 1, Math.max(visibleCommands.length - 1, 0));
            renderCommandPalette();
            return;
          }
          if (event.key === "ArrowUp") {
            event.preventDefault();
            commandCursor = Math.max(commandCursor - 1, 0);
            renderCommandPalette();
            return;
          }
          if (event.key === "Enter" && visibleCommands[commandCursor]) {
            event.preventDefault();
            closeCommandPalette();
            visibleCommands[commandCursor].run();
          }
        });
        if (cmdkInput) cmdkInput.addEventListener("input", () => { commandCursor = 0; renderCommandPalette(); });
        if (cmdkOverlay) cmdkOverlay.addEventListener("click", (event) => { if (event.target === cmdkOverlay) closeCommandPalette(); });

        async function loadObservations() {
          try {
            const response = await fetch("/actors/" + encodeURIComponent(actorId) + "/observations?limit=500", { headers: { "Accept": "application/json" } });
            if (!response.ok) return;
            const payload = await response.json();
            const items = Array.isArray(payload.items) ? payload.items : [];
            items.forEach((item) => {
              observationStore.set(observationMapKey(item.item_type, item.item_key), item);
            });
            observationCards.forEach(applyObservationCard);
            renderObservationLedger();
          } catch (error) {
            // Keep page usable even if observation endpoint is unavailable.
          }
        }

        observationCards.forEach((card) => {
          const saveButton = card.querySelector(".observation-save");
          if (!saveButton) return;
          saveButton.addEventListener("click", async () => {
            const itemType = card.dataset.observationItemType || "";
            const itemKey = card.dataset.observationItemKey || "";
            const updatedBy = String((card.querySelector(".observation-analyst") || {}).value || "");
            const confidence = String((card.querySelector(".observation-confidence") || {}).value || "moderate");
            const sourceReliability = String((card.querySelector(".observation-source-reliability") || {}).value || "");
            const informationCredibility = String((card.querySelector(".observation-information-credibility") || {}).value || "");
            const sourceRef = String((card.querySelector(".observation-source-ref") || {}).value || "");
            const note = String((card.querySelector(".observation-note") || {}).value || "");
            const payload = {
              updated_by: updatedBy,
              confidence: confidence,
              source_reliability: sourceReliability,
              information_credibility: informationCredibility,
              source_ref: sourceRef,
              note: note
            };
            try {
              const metaNode = card.querySelector("[data-observation-meta]");
              if (metaNode) metaNode.textContent = "Saving...";
              const response = await fetch(
                "/actors/" + encodeURIComponent(actorId) + "/observations/" + encodeURIComponent(itemType) + "/" + encodeURIComponent(itemKey),
                { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify(payload) }
              );
              if (!response.ok) {
                const metaNode = card.querySelector("[data-observation-meta]");
                if (metaNode) metaNode.textContent = "Save failed. Retry.";
                return;
              }
              const data = await response.json();
              observationStore.set(observationMapKey(itemType, itemKey), data);
              observationCards
                .filter((candidate) => (candidate.dataset.observationItemType || "") === itemType && (candidate.dataset.observationItemKey || "") === itemKey)
                .forEach(applyObservationCard);
              renderObservationLedger();
            } catch (error) {
              const metaNode = card.querySelector("[data-observation-meta]");
              if (metaNode) metaNode.textContent = "Save failed. Retry.";
            }
          });
        });

        if (ledgerApply) ledgerApply.addEventListener("click", renderObservationLedger);
        if (ledgerClear) {
          ledgerClear.addEventListener("click", () => {
            if (ledgerFilterAnalyst) ledgerFilterAnalyst.value = "";
            if (ledgerFilterConfidence) ledgerFilterConfidence.value = "";
            if (ledgerFilterFrom) ledgerFilterFrom.value = "";
            if (ledgerFilterTo) ledgerFilterTo.value = "";
            if (ledgerLimit) ledgerLimit.value = "12";
            renderObservationLedger();
          });
        }

        loadObservations();
        renderTimelineChips();
        renderSinceReview();

      })();
