(function () {
  const payloadNode = document.getElementById("scan-catalog-json");
  const filtersNode = document.getElementById("scan-category-filters");
  const cardsNode = document.getElementById("scan-cards-grid");
  const scanTypeField = document.getElementById("scan-type-field");
  const scanTypeFallbackWrapper = document.getElementById("scan-type-fallback-wrapper");
  const compareGrid = document.getElementById("scan-compare-grid");
  const compareEmpty = document.getElementById("scan-compare-empty");
  const compareToggle = document.getElementById("scan-compare-toggle");
  const compareToggleLabel = document.getElementById("scan-compare-toggle-label");
  const compareContent = document.getElementById("scan-compare-content");
  const whyObjective = document.getElementById("scan-why-objective");
  const whyWhenToUse = document.getElementById("scan-why-when-to-use");
  const whyWhenNotToUse = document.getElementById("scan-why-when-not-to-use");
  const whyOutput = document.getElementById("scan-why-output");
  const whyLimits = document.getElementById("scan-why-limits");
  const glossaryTooltip = document.getElementById("glossary-tooltip");
  const glossaryTooltipContent = document.getElementById("glossary-tooltip-content");
  const glossaryButtons = document.querySelectorAll("[data-glossary-term]");
  const guidedForm = document.getElementById("guided-scan-form");
  const stepPanels = document.querySelectorAll("[data-step-panel]");
  const stepIndicators = document.querySelectorAll("[data-step-indicator]");
  const stepNext = document.getElementById("scan-step-next");
  const stepPrev = document.getElementById("scan-step-prev");
  const currentStepLabel = document.getElementById("scan-current-step-label");
  const riskBadge = document.getElementById("scan-risk-badge");
  const invasivenessBadge = document.getElementById("scan-invasiveness-badge");
  const noiseBadge = document.getElementById("scan-noise-badge");
  const riskSummary = document.getElementById("scan-risk-summary");
  const errorSummary = document.getElementById("guided-form-error-summary");
  const errorSummaryList = document.getElementById("guided-form-error-list");
  const targetInput = guidedForm?.querySelector("input[name='target']");
  const targetError = document.getElementById("target-error");
  const learningGoalError = document.getElementById("learning-goal-error");
  const didacticModeRadios = guidedForm?.querySelectorAll("input[name='didactic_mode']");
  const didacticModeGuidance = document.getElementById("didactic-mode-guidance");
  const scopeAcknowledged = document.getElementById("scope-acknowledged");
  const scopeAuthorizationError = document.getElementById("scope-authorization-error");
  const consentError = document.getElementById("consent-error");
  const runComplianceAcknowledged = document.getElementById("run-compliance-acknowledged");
  const runComplianceError = document.getElementById("run-compliance-error");
  const moduleSelector = document.getElementById("scan-module-selector");
  const moduleSelectionError = document.getElementById("module-selection-error");
  const moduleSelectionFieldset = moduleSelectionError?.closest("fieldset");
  const selectedModulesInput = document.getElementById("selected-modules-json");
  const modulesSummary = document.getElementById("scan-modules-summary");
  const advancedModulesList = document.getElementById("advanced-module-config-list");
  const advancedModulesInput = document.getElementById("advanced-modules-json");
  const impactDuration = document.getElementById("scan-impact-duration");
  const impactNoise = document.getElementById("scan-impact-noise");
  const impactRisk = document.getElementById("scan-impact-risk");
  const impactNote = document.getElementById("scan-impact-note");
  const impactConfidence = document.getElementById("scan-impact-confidence");

  if (
    !payloadNode ||
    !filtersNode ||
    !cardsNode ||
    !scanTypeField ||
    !compareGrid ||
    !compareEmpty ||
    !compareToggle ||
    !compareToggleLabel ||
    !compareContent ||
    !whyObjective ||
    !whyWhenToUse ||
    !whyWhenNotToUse ||
    !whyOutput ||
    !whyLimits ||
    !glossaryTooltip ||
    !glossaryTooltipContent ||
    !guidedForm ||
    stepPanels.length === 0 ||
    stepIndicators.length === 0 ||
    !stepNext ||
    !stepPrev ||
    !riskBadge ||
    !invasivenessBadge ||
    !noiseBadge ||
    !riskSummary ||
    !errorSummary ||
    !errorSummaryList ||
    !targetInput ||
    !targetError ||
    !learningGoalError ||
    !didacticModeRadios ||
    didacticModeRadios.length === 0 ||
    !didacticModeGuidance ||
    !scopeAcknowledged ||
    !scopeAuthorizationError ||
    !consentError ||
    !runComplianceAcknowledged ||
    !runComplianceError ||
    !moduleSelector ||
    !moduleSelectionError ||
    !selectedModulesInput ||
    !modulesSummary ||
    !advancedModulesList ||
    !advancedModulesInput ||
    !impactDuration ||
    !impactNoise ||
    !impactRisk ||
    !impactNote ||
    !impactConfidence ||
    glossaryButtons.length === 0
  ) {
    return;
  }

  let catalog;
  try {
    catalog = JSON.parse(payloadNode.textContent || "[]");
  } catch (_error) {
    return;
  }

  if (!Array.isArray(catalog) || catalog.length === 0) {
    return;
  }

  const categories = ["Tutte", ...new Set(catalog.map((entry) => entry.category))];
  if (!scanTypeField.value && catalog[0]?.id) {
    scanTypeField.value = catalog[0].id;
  }
  const selectedForCompare = new Set();
  let activeCategory = "Tutte";
  let currentStep = 1;
  let mobileCompareExpanded = false;
  let selectedModules = new Set();
  let advancedModuleConfig = {};
  let recommendedScanType = "";
  const MAX_COMPARE = 6;
  const goalToScan = { baseline: "light", verification: "light", deep_dive: "full" };
  const goalLabels = {
    baseline: "mappare l'esposizione iniziale",
    verification: "verificare una correzione",
    deep_dive: "approfondimento tecnico completo",
  };
  const totalSteps = stepPanels.length;
  const csrfTokenInput = guidedForm.querySelector("input[name='csrf_token']");
  const telemetrySessionId =
    window.crypto?.randomUUID?.() ||
    `sb-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  let stepEnteredAtMs = performance.now();
  let lastValidationErrorCount = 0;

  function sendScanBuilderTelemetry(eventType, overrides = {}) {
    const payload = {
      session_id: telemetrySessionId,
      step: overrides.step || currentStep,
      event_type: eventType,
      didactic_mode: selectedDidacticMode(),
      ...overrides,
    };
    if (!csrfTokenInput?.value) {
      return;
    }
    fetch("/api/v1/telemetry/scan-builder", {
      method: "POST",
      credentials: "same-origin",
      keepalive: true,
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfTokenInput.value,
      },
      body: JSON.stringify(payload),
    }).catch(() => {
      // Telemetria best-effort: non deve alterare UX o flusso scansione.
    });
  }

  function elapsedStepDecisionTimeMs() {
    return Math.max(0, Math.round(performance.now() - stepEnteredAtMs));
  }

  function setFieldValidationState(field, hasError) {
    if (!field) {
      return;
    }
    field.setAttribute("aria-invalid", hasError ? "true" : "false");
    field.classList.toggle("form-control-invalid", hasError);
  }

  const levelStyles = {
    beginner: "bg-emerald-500/20 text-emerald-200 border-emerald-400/40",
    intermediate: "bg-amber-500/20 text-amber-200 border-amber-400/40",
    pro: "bg-rose-500/20 text-rose-200 border-rose-400/40",
  };
  const glossaryDefinitions = {
    owasp:
      "OWASP Top 10 è una lista aggiornata periodicamente delle vulnerabilità web più critiche.",
    cvss:
      "CVSS è il punteggio standard (0-10) che stima la gravità tecnica di una vulnerabilità.",
    false_positive:
      "Un false positive è un alert non confermato: richiede sempre validazione manuale prima della remediation.",
  };
  const stepLabels = {
    1: "Obiettivo utente",
    2: "Scansione consigliata",
    3: "Consenso legale",
    4: "Impatto operativo",
    5: "Checklist compliance",
  };
  const didacticModeLimits = {
    beginner: { timeoutSeconds: 30, maxPayloads: 40 },
    analyst: { timeoutSeconds: 90, maxPayloads: 80 },
    expert: { timeoutSeconds: 300, maxPayloads: 500 },
  };
  const parameterExplainability = {
    timeout_seconds: {
      title: "Timeout (secondi)",
      whatChanges:
        "Aumenta la finestra di esecuzione del modulo: utile su target lenti, ma allunga la durata complessiva della run.",
      tradeOff:
        "Timeout troppo alto può saturare la finestra operativa e generare rumore prolungato su sistemi monitorati.",
      falsePositiveImpact:
        "Troppo basso può interrompere test legittimi e creare risultati incompleti (falsi negativi).",
      antiPattern:
        "Impostare il massimo per tutti i moduli senza una motivazione tecnica documentata.",
      practicalExample:
        "Esempio: porta timeout da 20s a 45s solo per moduli su endpoint storicamente lenti.",
    },
    max_payloads: {
      title: "Budget payload",
      whatChanges:
        "Definisce quanti payload inviare per modulo: più payload = copertura maggiore e maggiore probabilità di finding.",
      tradeOff:
        "Valori alti aumentano traffico, tempi e probabilità di impatto operativo (rate-limit, WAF alert, log rumorosi).",
      falsePositiveImpact:
        "Valori molto bassi possono ridurre i segnali utili e nascondere vulnerabilità reali.",
      antiPattern:
        "Aumentare il budget payload in modalità Expert senza validare prima il comportamento con una run light.",
      practicalExample:
        "Esempio: passa da 30 a 60 payload dopo aver verificato che la baseline non copre un vettore OWASP prioritario.",
    },
  };

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function normalizeLevel(level) {
    return (level || "intermediate").toLowerCase();
  }

  function riskScoreFromLabel(label) {
    const normalized = String(label || "").toLowerCase();
    if (
      normalized.includes("alta") ||
      normalized.includes("alto") ||
      normalized.includes("high") ||
      normalized.includes("aggressiva")
    ) {
      return 3;
    }
    if (
      normalized.includes("media") ||
      normalized.includes("medio") ||
      normalized.includes("moder")
    ) {
      return 2;
    }
    return 1;
  }

  function riskUiForScore(score) {
    if (score >= 3) {
      return {
        badgeClass: "border-rose-400/60 text-rose-100 bg-rose-500/20",
        panelClass: "border-rose-400/40 bg-rose-500/10",
        label: "Rischio alto",
        summary:
          "Questa scansione è invasiva o rumorosa: pianifica una finestra autorizzata e avvisa i team operativi prima del run.",
      };
    }

    if (score === 2) {
      return {
        badgeClass: "border-amber-300/60 text-amber-100 bg-amber-500/20",
        panelClass: "border-amber-400/40 bg-amber-500/10",
        label: "Rischio medio",
        summary:
          "Questa scansione può generare traffico operativo visibile: verifica il perimetro autorizzato prima della submission.",
      };
    }

    return {
      badgeClass: "border-emerald-300/60 text-emerald-100 bg-emerald-500/20",
      panelClass: "border-emerald-400/40 bg-emerald-500/10",
      label: "Rischio basso",
      summary:
        "Questa scansione è a bassa invasività: resta comunque obbligatorio il consenso e la validazione del target.",
    };
  }

  function priorityRiskAdjustment() {
    const { value } = getPriorityInfo();
    if (value >= 7) {
      return 1; // Alta / Critica → maggiore rischio operativo
    }
    if (value <= 3) {
      return -1; // Bassa / Minima → minore urgenza/impatto
    }
    return 0; // Media
  }

  function riskScoreFromEntry(entry) {
    return Math.max(
      riskScoreFromLabel(entry.invasiveness),
      riskScoreFromLabel(entry.noise_level)
    );
  }

  function riskUiFromEntry(entry) {
    // Il rischio mostrato combina l'invasività/rumore della scansione con la
    // priorità scelta: il tag (e non solo la descrizione) cambia di conseguenza.
    const base = riskScoreFromEntry(entry);
    const combined = Math.min(3, Math.max(1, base + priorityRiskAdjustment()));
    return riskUiForScore(combined);
  }

  function getPriorityInfo() {
    const select = guidedForm.querySelector("select[name='priority']");
    if (!select) {
      return { value: 5, label: "Media" };
    }
    const value = Number(select.value) || 5;
    const label = select.options[select.selectedIndex]?.text || "Media";
    return { value, label };
  }

  function priorityNote() {
    const { value, label } = getPriorityInfo();
    if (value >= 7) {
      return ` Priorità impostata su ${label}: trattala come run prioritaria — concorda una finestra operativa e avvisa i team operativi prima di avviare.`;
    }
    if (value <= 3) {
      return ` Priorità ${label}: nessuna urgenza di pianificazione; eseguila quando preferisci, sempre entro lo scope autorizzato.`;
    }
    return ` Priorità ${label}: pianificazione ordinaria.`;
  }

  function updateRiskPanel(entry) {
    const ui = riskUiFromEntry(entry);
    const normalizedInvasiveness = String(entry.invasiveness || "non specificata");
    const normalizedNoise = String(entry.noise_level || "non specificato");

    riskBadge.className = `inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${ui.badgeClass}`;
    riskBadge.textContent = ui.label;
    invasivenessBadge.textContent = `Invasività: ${normalizedInvasiveness}`;
    noiseBadge.textContent = `Rumore: ${normalizedNoise}`;
    riskSummary.textContent = ui.summary + priorityNote();

    const panel = riskBadge.closest("#scan-risk-panel");
    if (panel) {
      panel.className = `rounded-lg border p-4 ${ui.panelClass}`;
    }
  }

  function visibleEntries() {
    if (activeCategory === "Tutte") {
      return catalog;
    }
    return catalog.filter((entry) => entry.category === activeCategory);
  }

  function renderFilters() {
    filtersNode.innerHTML = "";
    categories.forEach((category) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `rounded-full px-3 py-1.5 text-xs border transition ${
        category === activeCategory
          ? "border-cyan-300 bg-cyan-400/20 text-cyan-100"
          : "border-slate-700 bg-slate-900 text-slate-300 hover:border-slate-500"
      }`;
      button.textContent = category;
      button.addEventListener("click", () => {
        activeCategory = category;
        renderFilters();
        renderCards();
      });
      filtersNode.appendChild(button);
    });
  }

  function compareCard(entry) {
    const node = document.createElement("article");
    node.className = "rounded-lg border border-slate-700 bg-slate-900/90 p-3";

    const displayName = escapeHtml(entry.display_name);
    const expectedDuration = escapeHtml(entry.expected_duration);
    const invasiveness = escapeHtml(entry.invasiveness);
    const owaspCoverage = escapeHtml(((entry.owasp_tags || []).join(", ")) || "N/A");
    const objective = escapeHtml(entry.learning_objective || "");
    const whenToUse = escapeHtml(entry.when_to_use || "");

    node.innerHTML = `
      <h4 class="font-semibold text-sm">${displayName}</h4>
      ${objective ? `<p class="mt-1 text-xs text-slate-200">${objective}</p>` : ""}
      <ul class="mt-2 space-y-1 text-xs text-slate-300">
        <li><span class="text-slate-400">Cosa fa:</span> ${objective || "—"}</li>
        <li><span class="text-slate-400">Quando usarla:</span> ${whenToUse || "—"}</li>
        <li><span class="text-slate-400">Durata:</span> ${expectedDuration}</li>
        <li><span class="text-slate-400">Invasività:</span> ${invasiveness}</li>
        <li><span class="text-slate-400">Copertura OWASP:</span> ${owaspCoverage}</li>
      </ul>
    `;
    return node;
  }

  function renderCompare() {
    const selectedEntries = catalog.filter((entry) => selectedForCompare.has(entry.id));
    compareGrid.innerHTML = "";
    if (selectedEntries.length < 2) {
      compareEmpty.classList.remove("hidden");
      return;
    }
    compareEmpty.classList.add("hidden");
    selectedEntries.forEach((entry) => compareGrid.appendChild(compareCard(entry)));
  }

  function updateCompareToggleUi() {
    const isDesktop = window.matchMedia("(min-width: 768px)").matches;
    const isExpanded = isDesktop || mobileCompareExpanded;

    compareContent.classList.toggle("hidden", !isExpanded);
    compareToggle.setAttribute("aria-expanded", String(isExpanded));
    compareToggleLabel.textContent = isExpanded ? "Chiudi confronto" : "Apri confronto";
  }

  function updateSelectedScan(scanType) {
    scanTypeField.value = scanType;
    const selectedEntry = catalog.find((entry) => entry.id === scanType);
    if (!selectedEntry) {
      return;
    }

    updateRiskPanel(selectedEntry);
    whyObjective.textContent = selectedEntry.learning_objective || "Nessun obiettivo didattico disponibile.";
    whyWhenToUse.textContent = selectedEntry.when_to_use || "Indicazioni non disponibili.";
    whyWhenNotToUse.textContent = selectedEntry.when_not_to_use || "Limitazioni non disponibili.";
    whyOutput.textContent = selectedEntry.interpretation_guide || "Guida all'interpretazione non disponibile.";

    const falsePositives = Array.isArray(selectedEntry.common_false_positives)
      ? selectedEntry.common_false_positives
      : [];
    whyLimits.textContent =
      falsePositives.length > 0
        ? falsePositives.join(" · ")
        : "Possibili falsi positivi non documentati per questa tipologia di analisi.";
    renderModuleSelector(selectedEntry);
  }

  function getSelectedEntry() {
    return catalog.find((entry) => entry.id === scanTypeField.value);
  }

  function selectedDidacticMode() {
    const selected = guidedForm.querySelector("input[name='didactic_mode']:checked");
    return selected?.value || "analyst";
  }

  function getModeLimits() {
    return didacticModeLimits[selectedDidacticMode()] || didacticModeLimits.analyst;
  }

  function applyDidacticModeGuidance() {
    const mode = selectedDidacticMode();
    if (mode === "beginner") {
      didacticModeGuidance.textContent =
        "Beginner attivo: moduli ad alto rischio disabilitati e limiti timeout/payload più conservativi.";
      return;
    }
    if (mode === "expert") {
      didacticModeGuidance.textContent =
        "Expert attivo: pieno controllo client-side. Restano attivi i guardrail centralizzati del server.";
      return;
    }
    didacticModeGuidance.textContent =
      "Analyst attivo: limiti intermedi con bilanciamento tra copertura tecnica e sicurezza operativa.";
  }

  function updateSelectedModulesInput() {
    selectedModulesInput.value = JSON.stringify(Array.from(selectedModules));
    const normalizedConfig = {};
    Array.from(selectedModules).forEach((moduleId) => {
      if (advancedModuleConfig[moduleId]) {
        normalizedConfig[moduleId] = advancedModuleConfig[moduleId];
      }
    });
    advancedModuleConfig = normalizedConfig;
    advancedModulesInput.value = JSON.stringify(advancedModuleConfig);
    if (selectedModules.size > 0) {
      moduleSelectionError.classList.add("hidden");
    }
    updateImpactSimulation(getSelectedEntry());
  }

  function updateModulesSummary(entry) {
    const modules = Array.isArray(entry?.modules) ? entry.modules : [];
    const labelMap = new Map(modules.map((module) => [module.id, module.label || module.id]));
    if (selectedModules.size === 0) {
      modulesSummary.textContent = "Nessun modulo selezionato.";
      return;
    }
    const labels = Array.from(selectedModules)
      .map((moduleId) => labelMap.get(moduleId) || moduleId)
      .join(", ");
    modulesSummary.textContent = labels;
  }

  function updateImpactSimulation(entry) {
    if (!entry) {
      return;
    }

    const baseMinutesMap = { light: 8, full: 34, wordpress: 22 };
    const baseMinutes = baseMinutesMap[entry.id] || 18;
    const selectedModulesCount = Math.max(1, selectedModules.size);
    const moduleFactor = 1 + (selectedModulesCount - 1) * 0.18;

    let timeoutAccumulator = 0;
    let payloadAccumulator = 0;
    Array.from(selectedModules).forEach((moduleId) => {
      const config = advancedModuleConfig[moduleId];
      timeoutAccumulator += Number(config?.timeout_seconds || 20);
      payloadAccumulator += Number(config?.max_payloads || 30);
    });

    const avgTimeout = timeoutAccumulator / selectedModulesCount;
    const avgPayloads = payloadAccumulator / selectedModulesCount;
    const timeoutFactor = Math.min(2.2, Math.max(0.7, avgTimeout / 20));
    const payloadFactor = Math.min(2.2, Math.max(0.7, avgPayloads / 30));
    const estimatedMinutes = Math.max(
      4,
      Math.round(baseMinutes * moduleFactor * timeoutFactor * payloadFactor)
    );

    const baseNoiseScore = riskScoreFromLabel(entry.noise_level);
    const baseRiskScore = riskScoreFromLabel(entry.invasiveness);
    const tuningScore = (avgPayloads >= 70 ? 1 : 0) + (avgTimeout >= 45 ? 1 : 0);
    const noiseScore = Math.min(3, Math.max(1, baseNoiseScore + (tuningScore > 0 ? 1 : 0)));
    const riskScore = Math.min(3, Math.max(1, Math.max(baseRiskScore, noiseScore)));
    const levelByScore = { 1: "Basso", 2: "Medio", 3: "Alto" };

    impactDuration.textContent = `~ ${estimatedMinutes} min`;
    impactNoise.textContent = levelByScore[noiseScore] || "Medio";
    impactRisk.textContent = levelByScore[riskScore] || "Medio";
    impactNote.textContent =
      riskScore >= 3
        ? "Impatto elevato: pianifica finestra concordata, monitoraggio SOC e strategia di rollback prima dell'avvio."
        : "Stima utile per preparare il run: verifica comunque autorizzazioni, disponibilità operativa e finestre di manutenzione.";
    impactConfidence.textContent =
      selectedModules.size <= 1 ? "Stima preliminare" : "Stima modulare";
  }

  function renderModuleSelector(entry) {
    const modules = Array.isArray(entry?.modules) ? entry.modules : [];
    const modulesSet = new Set(modules.map((module) => module.id));
    const filteredSelection = Array.from(selectedModules).filter((moduleId) => modulesSet.has(moduleId));
    selectedModules = new Set(filteredSelection.length > 0 ? filteredSelection : modules.map((module) => module.id));

    moduleSelector.innerHTML = "";
    modules.forEach((module) => {
      const wrapper = document.createElement("label");
      wrapper.className = "flex items-start gap-2 rounded-md border border-slate-700 bg-slate-950/50 px-3 py-2 text-sm text-slate-200";

      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = module.id;
      checkbox.className = "mt-1 accent-cyan-400";
      checkbox.checked = selectedModules.has(module.id);
      const mode = selectedDidacticMode();
      const highRiskModules = new Set(["sqlmap", "commix", "nosqlmap"]);
      const isBeginnerBlocked = mode === "beginner" && highRiskModules.has(module.id);
      if (isBeginnerBlocked) {
        checkbox.checked = false;
        selectedModules.delete(module.id);
        delete advancedModuleConfig[module.id];
      }
      checkbox.disabled = isBeginnerBlocked;
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) {
          selectedModules.add(module.id);
        } else {
          selectedModules.delete(module.id);
          delete advancedModuleConfig[module.id];
        }
        updateSelectedModulesInput();
        updateModulesSummary(entry);
        renderAdvancedModuleConfig(entry);
        updateImpactSimulation(entry);
      });

      const text = document.createElement("span");
      const labelLine = document.createElement("span");
      labelLine.className = "block font-medium text-slate-100";
      labelLine.textContent = isBeginnerBlocked
        ? `${module.label || module.id} (bloccato in Beginner)`
        : module.label || module.id;
      text.appendChild(labelLine);
      if (module.description) {
        const desc = document.createElement("span");
        desc.className = "block text-xs text-slate-400 mt-0.5";
        desc.textContent = module.description;
        text.appendChild(desc);
      }
      wrapper.appendChild(checkbox);
      wrapper.appendChild(text);
      moduleSelector.appendChild(wrapper);
    });

    updateSelectedModulesInput();
    updateModulesSummary(entry);
    renderAdvancedModuleConfig(entry);
    updateImpactSimulation(entry);
  }

  function renderAdvancedModuleConfig(entry) {
    const modules = Array.isArray(entry?.modules) ? entry.modules : [];
    advancedModulesList.innerHTML = "";

    const selected = Array.from(selectedModules);
    if (selected.length === 0) {
      const emptyNote = document.createElement("p");
      emptyNote.className = "home-microcopy text-slate-500";
      emptyNote.textContent = "Seleziona almeno un modulo nello Step 2 per configurare parametri avanzati.";
      advancedModulesList.appendChild(emptyNote);
      return;
    }

    const timeoutExplainability = parameterExplainability.timeout_seconds;
    const payloadExplainability = parameterExplainability.max_payloads;

    // Spiegazione mostrata UNA volta sola (prima era ripetuta per ogni modulo):
    // riduce drasticamente la lunghezza della sezione.
    const help = document.createElement("details");
    help.className = "rounded-md border border-slate-700/80 bg-slate-900/60 p-3 text-[11px] text-slate-300";
    help.innerHTML = `
      <summary class="cursor-pointer font-semibold text-cyan-200">Come funzionano questi parametri</summary>
      <div class="mt-2 grid gap-3 sm:grid-cols-2">
        <div>
          <p class="font-semibold text-slate-100">${escapeHtml(timeoutExplainability.title)}</p>
          <ul class="mt-1 list-disc space-y-1 pl-4">
            <li><span class="font-semibold text-slate-100">Cosa cambia:</span> ${escapeHtml(timeoutExplainability.whatChanges)}</li>
            <li><span class="font-semibold text-slate-100">Trade-off:</span> ${escapeHtml(timeoutExplainability.tradeOff)}</li>
            <li><span class="font-semibold text-slate-100">Falsi positivi:</span> ${escapeHtml(timeoutExplainability.falsePositiveImpact)}</li>
          </ul>
        </div>
        <div>
          <p class="font-semibold text-slate-100">${escapeHtml(payloadExplainability.title)}</p>
          <ul class="mt-1 list-disc space-y-1 pl-4">
            <li><span class="font-semibold text-slate-100">Cosa cambia:</span> ${escapeHtml(payloadExplainability.whatChanges)}</li>
            <li><span class="font-semibold text-slate-100">Trade-off:</span> ${escapeHtml(payloadExplainability.tradeOff)}</li>
            <li><span class="font-semibold text-slate-100">Falsi positivi:</span> ${escapeHtml(payloadExplainability.falsePositiveImpact)}</li>
          </ul>
        </div>
      </div>`;
    advancedModulesList.appendChild(help);

    const modeLimits = getModeLimits();
    selected.forEach((moduleId) => {
      const moduleEntry = modules.find((module) => module.id === moduleId);
      const moduleLabel = moduleEntry?.label || moduleId;
      const current = advancedModuleConfig[moduleId] || { timeout_seconds: 20, max_payloads: 30 };
      const boundedTimeout = Math.min(current.timeout_seconds, modeLimits.timeoutSeconds);
      const boundedPayloads = Math.min(current.max_payloads, modeLimits.maxPayloads);
      advancedModuleConfig[moduleId] = {
        timeout_seconds: boundedTimeout,
        max_payloads: boundedPayloads,
      };

      // Ogni modulo è una riga collassabile compatta (chiusa di default).
      const row = document.createElement("details");
      row.className = "rounded-md border border-slate-700 bg-slate-950/60 px-3 py-2";
      row.innerHTML = `
        <summary class="flex cursor-pointer items-center justify-between gap-3 text-xs">
          <span class="font-semibold text-slate-100">${escapeHtml(moduleLabel)}</span>
          <span class="text-slate-400" data-advanced-summary="${moduleId}">timeout ${boundedTimeout}s &middot; ${boundedPayloads} payload</span>
        </summary>
        <div class="mt-2 grid gap-2 sm:grid-cols-2">
          <label class="grid gap-1 text-xs text-slate-300">
            <span>${escapeHtml(timeoutExplainability.title)} (max ${modeLimits.timeoutSeconds})</span>
            <input type="number" min="1" max="${modeLimits.timeoutSeconds}" step="1" class="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-100" data-advanced-timeout="${moduleId}" value="${boundedTimeout}" />
          </label>
          <label class="grid gap-1 text-xs text-slate-300">
            <span>${escapeHtml(payloadExplainability.title)} (max ${modeLimits.maxPayloads})</span>
            <input type="number" min="1" max="${modeLimits.maxPayloads}" step="1" class="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-100" data-advanced-payloads="${moduleId}" value="${boundedPayloads}" />
          </label>
        </div>`;
      advancedModulesList.appendChild(row);
    });

    function refreshSummary(moduleId) {
      const cfg = advancedModuleConfig[moduleId] || {};
      const node = advancedModulesList.querySelector(`[data-advanced-summary="${moduleId}"]`);
      if (node) {
        node.textContent = `timeout ${cfg.timeout_seconds}s · ${cfg.max_payloads} payload`;
      }
    }

    advancedModulesList.querySelectorAll("[data-advanced-timeout]").forEach((input) => {
      input.addEventListener("change", () => {
        const moduleId = input.getAttribute("data-advanced-timeout");
        if (!moduleId) {
          return;
        }
        const parsed = Number.parseInt(input.value, 10);
        const timeout = Number.isFinite(parsed) ? parsed : 20;
        const boundedTimeout = Math.min(timeout, getModeLimits().timeoutSeconds);
        advancedModuleConfig[moduleId] = {
          ...(advancedModuleConfig[moduleId] || { max_payloads: 30 }),
          timeout_seconds: boundedTimeout,
        };
        input.value = String(boundedTimeout);
        refreshSummary(moduleId);
        updateSelectedModulesInput();
        updateImpactSimulation(entry);
      });
    });
    advancedModulesList.querySelectorAll("[data-advanced-payloads]").forEach((input) => {
      input.addEventListener("change", () => {
        const moduleId = input.getAttribute("data-advanced-payloads");
        if (!moduleId) {
          return;
        }
        const parsed = Number.parseInt(input.value, 10);
        const maxPayloads = Number.isFinite(parsed) ? parsed : 30;
        const boundedPayloads = Math.min(maxPayloads, getModeLimits().maxPayloads);
        advancedModuleConfig[moduleId] = {
          ...(advancedModuleConfig[moduleId] || { timeout_seconds: 20 }),
          max_payloads: boundedPayloads,
        };
        input.value = String(boundedPayloads);
        refreshSummary(moduleId);
        updateSelectedModulesInput();
        updateImpactSimulation(entry);
      });
    });
  }

  function renderCards() {
    const entries = visibleEntries();
    cardsNode.innerHTML = "";

    entries.forEach((entry, index) => {
      const isSelected = scanTypeField.value === entry.id || (!scanTypeField.value && index === 0);
      if (isSelected) {
        updateSelectedScan(entry.id);
      }

      const card = document.createElement("article");
      card.className = `rounded-xl border p-4 transition cursor-pointer ${
        isSelected
          ? "border-cyan-400 bg-cyan-500/10"
          : "border-slate-700 bg-slate-950/50 hover:border-slate-500"
      }`;
      card.setAttribute("role", "button");
      card.setAttribute("tabindex", "0");
      card.dataset.scanType = entry.id;
      const displayName = escapeHtml(entry.display_name);
      const level = escapeHtml(entry.level);
      const learningObjective = escapeHtml(entry.learning_objective);
      const expectedDuration = escapeHtml(entry.expected_duration);
      const invasiveness = escapeHtml(entry.invasiveness);
      const noiseLevel = escapeHtml(entry.noise_level);
      const owaspTags = escapeHtml(((entry.owasp_tags || []).slice(0, 2)).join(", "));
      const compareActionLabel = selectedForCompare.has(entry.id)
        ? "Rimuovi dal confronto"
        : "Aggiungi al confronto";
      const recommendedBadge = entry.id === recommendedScanType
        ? `<p class="mt-1 text-[11px] font-semibold text-emerald-300">★ Consigliato per il tuo obiettivo</p>`
        : "";

      card.innerHTML = `
        <div class="flex items-center justify-between gap-2">
          <h4 class="font-semibold text-sm">${displayName}</h4>
          <span class="text-[11px] rounded-full border px-2 py-0.5 ${levelStyles[normalizeLevel(entry.level)] || levelStyles.intermediate}">
            ${level}
          </span>
        </div>
        ${recommendedBadge}
        <p class="text-xs text-slate-300 mt-2">${learningObjective}</p>
        <div class="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-200">
          <span class="rounded-full border border-slate-600 px-2 py-0.5">⏱ ${expectedDuration}</span>
          <span class="rounded-full border border-slate-600 px-2 py-0.5">🛡 ${invasiveness}</span>
          <span class="rounded-full border border-slate-600 px-2 py-0.5">📶 ${noiseLevel}</span>
          <span class="rounded-full border border-slate-600 px-2 py-0.5">OWASP ${owaspTags}</span>
        </div>
        <button type="button" class="mt-3 text-xs text-cyan-300 underline" data-compare-toggle="${entry.id}">
          ${compareActionLabel}
        </button>
      `;

      const selectCard = () => {
        updateSelectedScan(entry.id);
        renderCards();
      };

      card.addEventListener("click", selectCard);
      card.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          selectCard();
        }
      });

      const compareButton = card.querySelector("[data-compare-toggle]");
      if (!compareButton) {
        cardsNode.appendChild(card);
        return;
      }

      compareButton.addEventListener("click", (event) => {
        event.stopPropagation();
        if (selectedForCompare.has(entry.id)) {
          selectedForCompare.delete(entry.id);
        } else if (selectedForCompare.size < MAX_COMPARE) {
          selectedForCompare.add(entry.id);
        }
        renderCards();
        renderCompare();
      });

      cardsNode.appendChild(card);
    });
  }

  function showGlossaryTerm(termKey) {
    const definition = glossaryDefinitions[termKey];
    if (!definition) {
      return;
    }
    glossaryTooltipContent.textContent = definition;
    glossaryTooltip.classList.remove("hidden");
  }

  function registerGlossaryInteractions() {
    glossaryButtons.forEach((button) => {
      const term = button.dataset.glossaryTerm;
      button.addEventListener("mouseenter", () => showGlossaryTerm(term));
      button.addEventListener("focus", () => showGlossaryTerm(term));
      button.addEventListener("click", () => showGlossaryTerm(term));
    });
  }

  function updateStepperUi() {
    stepPanels.forEach((panel) => {
      const panelStep = Number(panel.dataset.stepPanel);
      panel.classList.toggle("hidden", panelStep !== currentStep);
    });

    stepIndicators.forEach((indicator) => {
      const indicatorStep = Number(indicator.dataset.stepIndicator);
      const isActive = indicatorStep === currentStep;
      const variant = indicator.dataset.stepVariant === "compact" ? "compact" : "default";
      const spacingClasses = variant === "compact" ? "px-3 py-2 text-[11px]" : "p-3 text-xs";
      indicator.className = `rounded-lg border ${spacingClasses} ${
        isActive
          ? "border-cyan-400 bg-cyan-500/10"
          : "border-slate-700 bg-slate-950/50"
      }`;
      if (isActive) {
        indicator.setAttribute("aria-current", "step");
      } else {
        indicator.removeAttribute("aria-current");
      }
    });

    stepPrev.disabled = currentStep === 1;
    stepNext.classList.toggle("hidden", currentStep === totalSteps);
    if (currentStepLabel) {
      currentStepLabel.textContent = `Step corrente: ${currentStep}/${totalSteps} · ${stepLabels[currentStep] || "Flusso guidato"}`;
    }
  }

  function validateCurrentStep() {
    return validateSteps([currentStep]);
  }

  function validateSteps(stepsToValidate) {
    const shouldValidate = (stepNumber) => stepsToValidate.includes(stepNumber);
    const messages = [];

    if (shouldValidate(1)) {
      const goalInput = guidedForm.querySelector("input[name='learning_goal']:checked");
      if (!targetInput.value.trim()) {
        messages.push("Inserisci un target valido (dominio, URL base o IP autorizzato).");
        setFieldValidationState(targetInput, true);
        targetError.classList.remove("hidden");
        targetError.textContent =
          "Target mancante: inserisci dominio/IP senza path o query (esempio: https://example.com).";
      } else {
        setFieldValidationState(targetInput, false);
        targetError.classList.add("hidden");
        targetError.textContent = "";
      }
      if (!goalInput) {
        messages.push("Seleziona un obiettivo utente per rendere la raccomandazione di scan_type più chiara.");
        learningGoalError.classList.remove("hidden");
      } else {
        learningGoalError.classList.add("hidden");
      }

      if (!scopeAcknowledged.checked) {
        messages.push("Conferma il perimetro legale autorizzato prima di procedere con la scansione.");
        setFieldValidationState(scopeAcknowledged, true);
        scopeAuthorizationError.classList.remove("hidden");
      } else {
        setFieldValidationState(scopeAcknowledged, false);
        scopeAuthorizationError.classList.add("hidden");
      }
    }

    if (shouldValidate(2)) {
      if (selectedModules.size === 0) {
        messages.push("Step 2: seleziona almeno un modulo scanner da includere nella run.");
        moduleSelectionFieldset?.classList.add("form-control-invalid");
        moduleSelectionError.classList.remove("hidden");
      } else {
        moduleSelectionFieldset?.classList.remove("form-control-invalid");
        moduleSelectionError.classList.add("hidden");
      }
    }

    if (shouldValidate(3)) {
      const requiredChecks = guidedForm.querySelectorAll(
        "input[name='accept_privacy'], input[name='accept_terms']"
      );
      const hasMissingConsent = Array.from(requiredChecks).some((check) => !check.checked);
      requiredChecks.forEach((check) => {
        setFieldValidationState(check, hasMissingConsent && !check.checked);
      });

      if (hasMissingConsent) {
        messages.push("Conferma entrambi i consensi legali: Privacy Policy e Termini di Servizio.");
        consentError.classList.remove("hidden");
      } else {
        consentError.classList.add("hidden");
      }
    }

    if (shouldValidate(5)) {
      if (!runComplianceAcknowledged.checked) {
        messages.push("Conferma la checklist compliance pre-run prima di avviare la scansione.");
        setFieldValidationState(runComplianceAcknowledged, true);
        runComplianceError.classList.remove("hidden");
      } else {
        setFieldValidationState(runComplianceAcknowledged, false);
        runComplianceError.classList.add("hidden");
      }
    }

    if (messages.length === 0) {
      lastValidationErrorCount = 0;
      errorSummary.classList.add("hidden");
      errorSummaryList.innerHTML = "";
      return true;
    }

    lastValidationErrorCount = messages.length;
    errorSummaryList.innerHTML = "";
    messages.forEach((message) => {
      const listItem = document.createElement("li");
      listItem.textContent = message;
      errorSummaryList.appendChild(listItem);
    });
    errorSummary.classList.remove("hidden");
    errorSummary.focus();
    return false;
  }

  function scrollWizardIntoView() {
    const anchor = document.getElementById("new-scan-title") || guidedForm;
    if (anchor && typeof anchor.scrollIntoView === "function") {
      anchor.scrollIntoView({ block: "start" });
    }
  }

  stepNext.addEventListener("click", () => {
    if (!validateCurrentStep()) {
      sendScanBuilderTelemetry("validation_error", {
        validation_errors_count: lastValidationErrorCount,
      });
      return;
    }
    sendScanBuilderTelemetry("step_advance", {
      decision_time_ms: elapsedStepDecisionTimeMs(),
    });
    currentStep = Math.min(totalSteps, currentStep + 1);
    stepEnteredAtMs = performance.now();
    sendScanBuilderTelemetry("step_view");
    updateStepperUi();
    scrollWizardIntoView();
  });

  stepPrev.addEventListener("click", () => {
    sendScanBuilderTelemetry("step_back", {
      decision_time_ms: elapsedStepDecisionTimeMs(),
    });
    currentStep = Math.max(1, currentStep - 1);
    stepEnteredAtMs = performance.now();
    sendScanBuilderTelemetry("step_view");
    updateStepperUi();
    scrollWizardIntoView();
  });

  guidedForm.addEventListener("submit", (event) => {
    if (!validateSteps([1, 2, 3, 5])) {
      event.preventDefault();
      sendScanBuilderTelemetry("validation_error", {
        step: currentStep,
        validation_errors_count: lastValidationErrorCount,
      });
      return;
    }
    sendScanBuilderTelemetry("submit", {
      step: 5,
      decision_time_ms: elapsedStepDecisionTimeMs(),
    });
    currentStep = 5;
    stepEnteredAtMs = performance.now();
    updateStepperUi();
  });

  targetInput.addEventListener("input", () => {
    if (!targetInput.value.trim()) {
      return;
    }
    setFieldValidationState(targetInput, false);
    targetError.classList.add("hidden");
    targetError.textContent = "";
  });

  scopeAcknowledged.addEventListener("change", () => {
    if (!scopeAcknowledged.checked) {
      return;
    }
    setFieldValidationState(scopeAcknowledged, false);
    scopeAuthorizationError.classList.add("hidden");
  });

  runComplianceAcknowledged.addEventListener("change", () => {
    if (!runComplianceAcknowledged.checked) {
      return;
    }
    setFieldValidationState(runComplianceAcknowledged, false);
    runComplianceError.classList.add("hidden");
  });

  didacticModeRadios.forEach((radio) => {
    radio.addEventListener("change", () => {
      applyDidacticModeGuidance();
      renderModuleSelector(getSelectedEntry());
    });
  });

  const learningGoalRadios = guidedForm.querySelectorAll("input[name='learning_goal']");
  const scanTypeGuidance = document.getElementById("scan-type-guidance");
  const defaultScanTypeGuidance = scanTypeGuidance ? scanTypeGuidance.innerHTML : "";

  function applyGoalRecommendation(goalValue) {
    const recommended = goalToScan[goalValue];
    const entry = recommended ? catalog.find((item) => item.id === recommended) : null;
    if (!entry) {
      recommendedScanType = "";
      if (scanTypeGuidance) {
        scanTypeGuidance.innerHTML = defaultScanTypeGuidance;
      }
      renderCards();
      return;
    }
    recommendedScanType = recommended;
    updateSelectedScan(recommended);
    renderCards();
    if (scanTypeGuidance) {
      scanTypeGuidance.innerHTML =
        `In base al tuo obiettivo (<span class="text-slate-200 font-medium">${escapeHtml(goalLabels[goalValue] || goalValue)}</span>) ` +
        `ti consigliamo <span class="text-cyan-200 font-semibold">${escapeHtml(entry.display_name)}</span>, ` +
        `già pre-selezionata qui sotto. Puoi comunque scegliere un'altra scansione dalle card.`;
    }
  }

  learningGoalRadios.forEach((radio) => {
    radio.addEventListener("change", () => {
      learningGoalError.classList.add("hidden");
      applyGoalRecommendation(radio.value);
    });
  });

  const prioritySelect = guidedForm.querySelector("select[name='priority']");
  if (prioritySelect) {
    prioritySelect.addEventListener("change", () => {
      const entry = getSelectedEntry();
      if (entry) {
        updateRiskPanel(entry);
      }
    });
  }

  compareToggle.addEventListener("click", () => {
    if (window.matchMedia("(min-width: 768px)").matches) {
      return;
    }
    mobileCompareExpanded = !mobileCompareExpanded;
    updateCompareToggleUi();
  });

  window.addEventListener("resize", updateCompareToggleUi);

  stepNext.classList.remove("hidden");
  stepPrev.classList.remove("hidden");
  if (scanTypeFallbackWrapper) {
    scanTypeFallbackWrapper.classList.add("hidden");
  }

  renderFilters();
  renderCards();
  renderCompare();
  updateSelectedModulesInput();
  updateModulesSummary(getSelectedEntry());
  updateImpactSimulation(getSelectedEntry());
  registerGlossaryInteractions();
  applyDidacticModeGuidance();
  updateStepperUi();
  updateCompareToggleUi();
  sendScanBuilderTelemetry("step_view", { step: 1 });
})();
