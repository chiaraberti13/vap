(function () {
  const payloadNode = document.getElementById("scan-catalog-json");
  const filtersNode = document.getElementById("scan-category-filters");
  const cardsNode = document.getElementById("scan-cards-grid");
  const hiddenScanType = document.getElementById("scan-type-selected");
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

  if (
    !payloadNode ||
    !filtersNode ||
    !cardsNode ||
    !hiddenScanType ||
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
  const selectedForCompare = new Set();
  let activeCategory = "Tutte";
  let currentStep = 1;
  let mobileCompareExpanded = false;
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
    hiddenScanType.value = scanType;
    const selectedEntry = catalog.find((entry) => entry.id === scanType);
    if (!selectedEntry) {
      return;
    }

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
  }

  function renderCards() {
    const entries = visibleEntries();
    cardsNode.innerHTML = "";

    entries.forEach((entry, index) => {
      const isSelected = hiddenScanType.value === entry.id || (!hiddenScanType.value && index === 0);
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
      indicator.className = `rounded-lg border p-3 text-xs ${
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
  }

  function validateCurrentStep() {
    if (currentStep === 1) {
      const targetInput = guidedForm.querySelector("input[name='target']");
      const goalInput = guidedForm.querySelector("input[name='learning_goal']:checked");
      if (!targetInput || !targetInput.value.trim()) {
        targetInput?.reportValidity();
        return false;
      }
      if (!goalInput) {
        const firstGoal = guidedForm.querySelector("input[name='learning_goal']");
        firstGoal?.reportValidity();
        return false;
      }
    }

    if (currentStep === 3) {
      const requiredChecks = guidedForm.querySelectorAll(
        "input[name='accept_privacy'], input[name='accept_terms']"
      );
      for (const check of requiredChecks) {
        if (!check.checked) {
          check.reportValidity();
          return false;
        }
      }
    }
    return true;
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

  compareToggle.addEventListener("click", () => {
    if (window.matchMedia("(min-width: 768px)").matches) {
      return;
    }
    mobileCompareExpanded = !mobileCompareExpanded;
    updateCompareToggleUi();
  });

  window.addEventListener("resize", updateCompareToggleUi);

  renderFilters();
  renderCards();
  renderCompare();
  registerGlossaryInteractions();
  updateStepperUi();
  updateCompareToggleUi();
})();
