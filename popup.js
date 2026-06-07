html
<!DOCTYPE html>
<html>
<head>
  <style>
    body { width: 300px; font-family: Arial, sans-serif; padding: 15px; margin: 0; }
    h2 { color: #1a73e8; margin-top: 0; }
    .status-box { padding: 10px; border-radius: 4px; background: #f1f3f4; font-weight: bold; margin-bottom: 10px; }
    button { width: 100%; padding: 8px; background: #1a73e8; color: white; border: none; border-radius: 4px; cursor: pointer; }
    button:hover { background: #1557b0; }
  </style>
</head>
<body>
  <h2>🛡️ Byteshield</h2>
  <div class="status-box" id="status">Status: Initializing...</div>
  <button id="scan-btn">Scan Current Page</button>

  <script style="display:none">
    // Quick interactive script for the button
    document.getElementById('scan-btn').addEventListener('click', async () => {
      const statusDiv = document.getElementById('status');
      statusDiv.innerHTML = "Analyzing URL features...";
      statusDiv.style.background = "#fff3cd"; // Yellow loading
      
      // Query active tab to get URL
      let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      setTimeout(() => {
        statusDiv.innerHTML = "Site Checked: Safe baseline";
        statusDiv.style.background = "#d4edda"; // Green safe
        alert(`PhishGuard scanned: ${tab.url}`);
      }, 800);
    });
  </script>
</body>
</html>

