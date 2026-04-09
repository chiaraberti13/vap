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
  const scopeAcknowledged = document.getElementById("scope-acknowledged");
  const scopeAuthorizationError = document.getElementById("scope-authorization-error");
  const consentError = document.getElementById("consent-error");
  const moduleSelector = document.getElementById("scan-module-selector");
  const moduleSelectionError = document.getElementById("module-selection-error");
  const selectedModulesInput = document.getElementById("selected-modules-json");
  const modulesSummary = document.getElementById("scan-modules-summary");

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
    !scopeAcknowledged ||
    !scopeAuthorizationError ||
    !consentError ||
    !moduleSelector ||
    !moduleSelectionError ||
    !selectedModulesInput ||
    !modulesSummary ||
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
  const totalSteps = stepPanels.length;

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
    4: "Conferma ed esecuzione",
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

  function riskUiFromEntry(entry) {
    const invasivenessScore = riskScoreFromLabel(entry.invasiveness);
    const noiseScore = riskScoreFromLabel(entry.noise_level);
    const combinedScore = Math.max(invasivenessScore, noiseScore);

    if (combinedScore >= 3) {
      return {
        badgeClass: "border-rose-400/60 text-rose-100 bg-rose-500/20",
        panelClass: "border-rose-400/40 bg-rose-500/10",
        label: "Rischio alto",
        summary:
          "Questa scansione è invasiva o rumorosa: pianifica una finestra autorizzata e avvisa i team operativi prima del run.",
      };
    }

    if (combinedScore === 2) {
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

  function updateRiskPanel(entry) {
    const ui = riskUiFromEntry(entry);
    const normalizedInvasiveness = String(entry.invasiveness || "non specificata");
    const normalizedNoise = String(entry.noise_level || "non specificato");

    riskBadge.className = `inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${ui.badgeClass}`;
    riskBadge.textContent = ui.label;
    invasivenessBadge.textContent = `Invasività: ${normalizedInvasiveness}`;
    noiseBadge.textContent = `Rumore: ${normalizedNoise}`;
    riskSummary.textContent = ui.summary;

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

    node.innerHTML = `
      <h4 class="font-semibold text-sm">${displayName}</h4>
      <ul class="mt-2 space-y-1 text-xs text-slate-300">
        <li><span class="text-slate-400">Durata:</span> ${expectedDuration}</li>
        <li><span class="text-slate-400">Invasività:</span> ${invasiveness}</li>
        <li><span class="text-slate-400">Copertura:</span> ${owaspCoverage}</li>
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

  function updateSelectedModulesInput() {
    selectedModulesInput.value = JSON.stringify(Array.from(selectedModules));
    if (selectedModules.size > 0) {
      moduleSelectionError.classList.add("hidden");
    }
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
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) {
          selectedModules.add(module.id);
        } else {
          selectedModules.delete(module.id);
        }
        updateSelectedModulesInput();
        updateModulesSummary(entry);
      });

      const text = document.createElement("span");
      text.textContent = module.label || module.id;
      wrapper.appendChild(checkbox);
      wrapper.appendChild(text);
      moduleSelector.appendChild(wrapper);
    });

    updateSelectedModulesInput();
    updateModulesSummary(entry);
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

      card.innerHTML = `
        <div class="flex items-center justify-between gap-2">
          <h4 class="font-semibold text-sm">${displayName}</h4>
          <span class="text-[11px] rounded-full border px-2 py-0.5 ${levelStyles[normalizeLevel(entry.level)] || levelStyles.intermediate}">
            ${level}
          </span>
        </div>
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
        } else if (selectedForCompare.size < 3) {
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
        targetInput.setAttribute("aria-invalid", "true");
        targetError.classList.remove("hidden");
        targetError.textContent =
          "Target mancante: inserisci dominio/IP senza path o query (esempio: https://example.com).";
      } else {
        targetInput.setAttribute("aria-invalid", "false");
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
        scopeAcknowledged.setAttribute("aria-invalid", "true");
        scopeAuthorizationError.classList.remove("hidden");
      } else {
        scopeAcknowledged.setAttribute("aria-invalid", "false");
        scopeAuthorizationError.classList.add("hidden");
      }
    }

    if (shouldValidate(2)) {
      if (selectedModules.size === 0) {
        messages.push("Step 2: seleziona almeno un modulo scanner da includere nella run.");
        moduleSelectionError.classList.remove("hidden");
      } else {
        moduleSelectionError.classList.add("hidden");
      }
    }

    if (shouldValidate(3)) {
      const requiredChecks = guidedForm.querySelectorAll(
        "input[name='accept_privacy'], input[name='accept_terms']"
      );
      const hasMissingConsent = Array.from(requiredChecks).some((check) => !check.checked);
      requiredChecks.forEach((check) => {
        check.setAttribute("aria-invalid", hasMissingConsent && !check.checked ? "true" : "false");
      });

      if (hasMissingConsent) {
        messages.push("Conferma entrambi i consensi legali: Privacy Policy e Termini di Servizio.");
        consentError.classList.remove("hidden");
      } else {
        consentError.classList.add("hidden");
      }
    }

    if (messages.length === 0) {
      errorSummary.classList.add("hidden");
      errorSummaryList.innerHTML = "";
      return true;
    }

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

  stepNext.addEventListener("click", () => {
    if (!validateCurrentStep()) {
      return;
    }
    currentStep = Math.min(totalSteps, currentStep + 1);
    updateStepperUi();
  });

  stepPrev.addEventListener("click", () => {
    currentStep = Math.max(1, currentStep - 1);
    updateStepperUi();
  });

  guidedForm.addEventListener("submit", () => {
    if (!validateSteps([1, 3])) {
      return;
    }
    currentStep = 4;
    updateStepperUi();
  });

  targetInput.addEventListener("input", () => {
    if (!targetInput.value.trim()) {
      return;
    }
    targetInput.setAttribute("aria-invalid", "false");
    targetError.classList.add("hidden");
    targetError.textContent = "";
  });

  scopeAcknowledged.addEventListener("change", () => {
    if (!scopeAcknowledged.checked) {
      return;
    }
    scopeAcknowledged.setAttribute("aria-invalid", "false");
    scopeAuthorizationError.classList.add("hidden");
  });

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
  registerGlossaryInteractions();
  updateStepperUi();
  updateCompareToggleUi();
})();
