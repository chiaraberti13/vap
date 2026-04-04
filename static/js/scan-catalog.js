(function () {
  const payloadNode = document.getElementById("scan-catalog-json");
  const filtersNode = document.getElementById("scan-category-filters");
  const cardsNode = document.getElementById("scan-cards-grid");
  const hiddenScanType = document.getElementById("scan-type-selected");
  const compareGrid = document.getElementById("scan-compare-grid");
  const compareEmpty = document.getElementById("scan-compare-empty");

  if (!payloadNode || !filtersNode || !cardsNode || !hiddenScanType || !compareGrid || !compareEmpty) {
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

  const levelStyles = {
    beginner: "bg-emerald-500/20 text-emerald-200 border-emerald-400/40",
    intermediate: "bg-amber-500/20 text-amber-200 border-amber-400/40",
    pro: "bg-rose-500/20 text-rose-200 border-rose-400/40",
  };

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
    node.innerHTML = `
      <h4 class="font-semibold text-sm">${entry.display_name}</h4>
      <ul class="mt-2 space-y-1 text-xs text-slate-300">
        <li><span class="text-slate-400">Durata:</span> ${entry.expected_duration}</li>
        <li><span class="text-slate-400">Invasività:</span> ${entry.invasiveness}</li>
        <li><span class="text-slate-400">Copertura:</span> ${(entry.owasp_tags || []).join(", ") || "N/A"}</li>
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

  function updateSelectedScan(scanType) {
    hiddenScanType.value = scanType;
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
      card.innerHTML = `
        <div class="flex items-center justify-between gap-2">
          <h4 class="font-semibold text-sm">${entry.display_name}</h4>
          <span class="text-[11px] rounded-full border px-2 py-0.5 ${levelStyles[normalizeLevel(entry.level)] || levelStyles.intermediate}">
            ${entry.level}
          </span>
        </div>
        <p class="text-xs text-slate-300 mt-2">${entry.learning_objective}</p>
        <div class="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-200">
          <span class="rounded-full border border-slate-600 px-2 py-0.5">⏱ ${entry.expected_duration}</span>
          <span class="rounded-full border border-slate-600 px-2 py-0.5">🛡 ${entry.invasiveness}</span>
          <span class="rounded-full border border-slate-600 px-2 py-0.5">📶 ${entry.noise_level}</span>
          <span class="rounded-full border border-slate-600 px-2 py-0.5">OWASP ${((entry.owasp_tags || []).slice(0, 2)).join(", ")}</span>
        </div>
        <button type="button" class="mt-3 text-xs text-cyan-300 underline" data-compare-toggle="${entry.id}">
          ${selectedForCompare.has(entry.id) ? "Rimuovi dal confronto" : "Aggiungi al confronto"}
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

  renderFilters();
  renderCards();
  renderCompare();
})();
