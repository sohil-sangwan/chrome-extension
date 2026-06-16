document.addEventListener('DOMContentLoaded', async () => {
  const statusBanner = document.getElementById('statusBanner');
  const metricUrlLength = document.getElementById('metricUrlLength');
  const metricDotCount = document.getElementById('metricDotCount');
  const metricHttps = document.getElementById('metricHttps');

  try {
    // 1. Get the active tab ID to request specific data from the background script
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    // 2. Request prediction data from background.js (Implementation details in Section 2)
    chrome.runtime.sendMessage({ action: "GET_LATEST_PREDICTION", tabId: tab.id }, (response) => {
      if (chrome.runtime.lastError || !response || !response.data) {
        statusBanner.textContent = "No data available";
        statusBanner.className = "status-banner status-loading";
        return;
      }

      const { prediction, metrics } = response.data;

      // 3. Update Extracted Feature UI items
      metricUrlLength.textContent = metrics.urlLength ?? 0;
      metricDotCount.textContent = metrics.dotCount ?? 0;
      metricHttps.textContent = metrics.isHttps ? "Secure (1)" : "Unsecure (0)";

      // 4. Transform UI state dynamically based on the ML pipeline classification verdict
      if (prediction === 1) {
        statusBanner.textContent = "Warning: Phishing Detected!";
        statusBanner.className = "status-banner status-phishing";
      } else if (prediction === 0) {
        statusBanner.textContent = "Safe Site";
        statusBanner.className = "status-banner status-safe";
      }
    });
  } catch (error) {
    console.error("Error updating ByteShield popup layout:", error);
  }
});
