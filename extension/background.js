importScripts('ort.min.js');

let session = null;

// Initialize the model once globally to optimize performance
async function initModel() {
  if (!session) {
    try {
      // Direct the ONNX engine to find the local .wasm files inside your root directory
      ort.env.wasm.wasmPaths = '/';
      
      // Load the model locally
      session = await ort.InferenceSession.create('./byteshield_model.onnx');
      console.log("ByteShield ONNX model loaded into background context.");
    } catch (err) {
      console.error("Failed to initialize ONNX session:", err);
    }
  }
}
initModel();

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Triggers when a page finishes loading completely
  if (changeInfo.status === 'complete' && tab.url) {
    let currentUrl = tab.url;
    
    // Completely ignore internal chrome configuration pages
    if (currentUrl.startsWith("chrome://") || currentUrl.startsWith("about:") || currentUrl.startsWith("chrome-extension://")) return;

    console.log("ByteShield background worker analyzing URL: " + currentUrl);

    // Transformed baseline feature array from Developer B data points
    let features = [
      currentUrl.length,                                // url_length
      (currentUrl.match(/\./g) || []).length,           // dot_count
      currentUrl.startsWith('https') ? 1 : 0,           // is_https
      0, 0, 0, 0                                        // Placeholders for local keyword array/Entropy
    ];
    
    try {
      await initModel(); // Ensure session is alive and ready
      if (!session) return;
      
      // Inference execution
      const inputTensor = new ort.Tensor('float32', features, [1, 7]);
      const feeds = { input: inputTensor };
      const results = await session.run(feeds);
      
      // Extract resulting calculations from your model's classification layers
      const output = results.output.data; 
      const phishingProbability = output[0];

      if (phishingProbability > 0.8) { 
        // Send a message directly to your Content Script to inject the warning banner
        chrome.tabs.sendMessage(tabId, { 
          action: "inject_warning", 
          reason: `Score: ${(phishingProbability * 100).toFixed(0)}%` 
        }).catch(err => console.log("Content script connection handshake pending on this page context."));
      }
    } catch (err) {
      console.error("Inference processing error:", err);
    }
  }
});