javascript
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Triggers when a page finishes loading
  if (changeInfo.status === 'complete' && tab.url) {
    console.log("Byteshield background worker analyzing URL: " + tab.url);
    // This is where we will eventually inject our ONNX ML model inference pipeline!
  }
});

