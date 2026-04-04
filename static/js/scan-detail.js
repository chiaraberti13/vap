(function initScanDetailPage() {
  const configElement = document.getElementById("scan-detail-config");
  if (!configElement) {
    return;
  }

  const config = JSON.parse(configElement.textContent || "{}");
  const scanId = Number(config.scanId);
  const apiKey = config.apiKey || "";

  if (!Number.isFinite(scanId)) {
    return;
  }

  const statusEl = document.getElementById("scan-status");
  const progressBar = document.getElementById("scan-progress-bar");
  const progressValue = document.getElementById("scan-progress-value");
  const logsContainer = document.getElementById("scan-logs");
  const notificationsContainer = document.getElementById("scan-notifications");
  const cancelButton = document.getElementById("cancel-scan");

  const renderEmptyState = (container, message) => {
    container.textContent = "";
    const paragraph = document.createElement("p");
    paragraph.className = "text-slate-500";
    paragraph.textContent = message;
    container.appendChild(paragraph);
  };

  const renderLogs = (logs) => {
    logsContainer.textContent = "";
    if (!logs.length) {
      renderEmptyState(logsContainer, "Nessun log disponibile.");
      return;
    }

    logs.forEach((entry) => {
      const line = document.createElement("p");
      const level = (entry.level || "info").toUpperCase();
      const levelColor = level === "ERROR" ? "text-red-400" : level === "WARNING" ? "text-yellow-400" : "text-cyan-400";

      const timestampText = document.createTextNode(`[${entry.timestamp || "--"}] `);
      const levelSpan = document.createElement("span");
      levelSpan.className = levelColor;
      levelSpan.textContent = level;
      const separatorText = document.createTextNode(" — ");
      const messageText = document.createTextNode(entry.message || "");

      line.appendChild(timestampText);
      line.appendChild(levelSpan);
      line.appendChild(separatorText);
      line.appendChild(messageText);
      logsContainer.appendChild(line);
    });

    logsContainer.scrollTop = logsContainer.scrollHeight;
  };

  const renderNotifications = (notifications) => {
    notificationsContainer.textContent = "";
    if (!notifications.length) {
      renderEmptyState(notificationsContainer, "In attesa di eventi critici.");
      return;
    }

    notifications.forEach((notification) => {
      const wrapper = document.createElement("div");
      wrapper.className = "rounded-lg border border-rose-400/40 bg-rose-500/10 px-3 py-2";

      const header = document.createElement("div");
      header.className = "flex items-center gap-2";

      const dot = document.createElement("span");
      dot.className = "inline-block w-2 h-2 rounded-full bg-rose-400";

      const title = document.createElement("span");
      title.className = "font-semibold text-rose-200 text-sm";
      title.textContent = notification.title || "Evento critico";

      const severity = document.createElement("span");
      severity.className = "ml-auto text-xs uppercase text-rose-300 font-bold";
      severity.textContent = notification.severity || "high";

      header.append(dot, title, severity);

      const description = document.createElement("p");
      description.className = "text-slate-200 mt-1 text-xs leading-relaxed";
      description.textContent = notification.description || "";

      wrapper.append(header, description);
      notificationsContainer.appendChild(wrapper);
    });
  };

  let socket;
  let reconnectAttempts = 0;
  const maxReconnectAttempts = 5;
  let allowReconnect = true;

  const handlePayload = (payload) => {
    if (payload.status && statusEl) {
      statusEl.textContent = payload.status;
    }

    if (typeof payload.progress === "number" && progressBar && progressValue) {
      progressBar.style.width = `${payload.progress}%`;
      progressValue.textContent = String(payload.progress);
    }

    renderLogs(payload.logs || []);
    renderNotifications(payload.notifications || []);

    if (["completed", "report_failed", "canceled"].includes(payload.status)) {
      if (cancelButton) {
        cancelButton.disabled = true;
        cancelButton.classList.add("opacity-50", "cursor-not-allowed");
      }
      allowReconnect = false;
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
      if (payload.status === "completed") {
        setTimeout(() => window.location.reload(), 1500);
      }
    }
  };

  const wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
  const wsUrl = `${wsProtocol}://${window.location.host}/ws?scan_id=${scanId}${apiKey ? `&api_key=${apiKey}` : ""}`;

  const connectWebSocket = () => {
    socket = new WebSocket(wsUrl);
    socket.onmessage = (event) => {
      handlePayload(JSON.parse(event.data));
    };
    socket.onopen = () => {
      reconnectAttempts = 0;
    };
    socket.onclose = () => {
      if (!allowReconnect || reconnectAttempts >= maxReconnectAttempts) {
        return;
      }
      const delay = Math.min(1000 * 2 ** reconnectAttempts, 10000);
      reconnectAttempts += 1;
      setTimeout(connectWebSocket, delay);
    };
    socket.onerror = () => {
      socket.close();
    };
  };

  connectWebSocket();

  if (cancelButton) {
    cancelButton.addEventListener("click", async () => {
      cancelButton.disabled = true;
      const response = await fetch(`/api/v1/scans/${scanId}/cancel${apiKey ? `?api_key=${apiKey}` : ""}`, { method: "POST" });
      if (!response.ok) {
        cancelButton.disabled = false;
      }
    });
  }
})();
