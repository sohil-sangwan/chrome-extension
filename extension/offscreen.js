let estimationSession = null;

// Clean array schema specifying the exact alphabetical sequence expected by Python
const ALPHABETICAL_FEATURES = [
    "contains_scam_keyword", // 1. Scanned keyword context
    "domain_entropy",        // 2. Entropy complexity indicator
    "dot_count",             // 3. Dot delimiter counts
    "is_https",              // 4. Secure socket layer indicator
    "is_risky_tld",          // 5. Unsafe top-level domain mapping
    "url_length"             // 6. Absolute character lengths
];

async function getModelSession() {
    if (estimationSession) return estimationSession;

    // Failsafe: if the WASM libraries or ONNX loader failed to inject dynamically
    if (typeof ort === 'undefined') {
        console.warn("[!] ONNX runtime library 'ort' is not defined. Active fallback mode enabled.");
        return null;
    }

    try {
        ort.env.wasm.wasmPaths = {
            'ort-wasm.wasm': chrome.runtime.getURL('ort-wasm.wasm'),
            'ort-wasm-simd.wasm': chrome.runtime.getURL('ort-wasm-simd.wasm'),
            'ort-wasm-simd-threaded.wasm': chrome.runtime.getURL('ort-wasm-simd-threaded.wasm'),
            'ort-wasm-simd-threaded.jsep.mjs': chrome.runtime.getURL('ort-wasm-simd-threaded.jsep.mjs'),
            'ort-wasm-simd-threaded.jsep.wasm': chrome.runtime.getURL('ort-wasm-simd-threaded.jsep.wasm')
        };

        estimationSession = await ort.InferenceSession.create(
            chrome.runtime.getURL('byteshield_model.onnx'),
            { executionProviders: ['wasm'] }
        );
        return estimationSession;
    } catch (err) {
        console.error("[-] Offscreen model compilation failed, relying on fallback parameters:", err);
        return null;
    }
}

// Pre-warm WebAssembly structures on document boot
getModelSession();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action !== "RUN_INFERENCE") return false;

    // Wrap the entire parsing loop in a try/catch to ensure we call sendResponse under any circumstance
    try {
        const { url, features } = message.payload || {};
        if (!features) {
            sendResponse({ prediction: 0, metrics: null, status: "error", error: "Missing features matrix" });
            return false;
        }

        // Execute asynchronous calculations without hanging the message passing bridge
        runInferenceChain(url, features)
            .then((result) => sendResponse(result))
            .catch((err) => {
                console.error("[-] Async prediction calculation rejected:", err);
                sendResponse({ prediction: 0, metrics: null, status: "error", error: err.message });
            });

        return true; // Keep the runtime messaging channel open for the asynchronous handler
    } catch (err) {
        console.error("[-] Synchronous crash inside offscreen intercept handler:", err);
        sendResponse({ prediction: 0, metrics: null, status: "error", error: err.message });
        return false;
    }
});

// Performs ML inference or executes local decision boundaries securely
async function runInferenceChain(url, features) {
    let prediction = 0;
    let inferenceSuccess = false;

    // 1. Arrange the features in strict alphabetical index order
    const sortedArray = ALPHABETICAL_FEATURES.map(key => {
        const val = features[key];
        return val !== undefined ? parseFloat(val) : 0.0;
    });

    try {
        const session = await getModelSession();
        if (session && typeof ort !== 'undefined') {
            // 2. Feed float32 values into a 1D evaluation tensor array (1 x N)
            const inputTensor = new ort.Tensor("float32", Float32Array.from(sortedArray), [1, sortedArray.length]);
            const feeds = { [session.inputNames[0]]: inputTensor };
            
            // 3. Execute ONNX Runtime engine
            const results = await session.run(feeds);
            const labelOutput = results[session.outputNames[0]];
            
            if (labelOutput && labelOutput.data) {
                prediction = Number(labelOutput.data[0]);
                inferenceSuccess = true;
            }
        }
    } catch (err) {
        console.error("[-] Fallback triggered. Machine Learning inference crashed:", err);
    }

    // ====================================================================
    // ROBUST FALLBACK BOUNDARY
    // Executed immediately if ort.js is blocked, uncompiled, or fails to resolve
    // ====================================================================
    if (!inferenceSuccess) {
        const scamWord = features["contains_scam_keyword"] ?? 0;
        const riskyTld = features["is_risky_tld"] ?? 0;
        const urlLen = features["url_length"] ?? 0;
        const dotCount = features["dot_count"] ?? 0;
        const isHttps = features["is_https"] ?? 1;

        // CRUCIAL FIX: Default to safe unless explicit scam keyword/risky TLD metrics match, 
        // preventing safe medium-length domains (like sarkariresult) from triggering blocks.
        if (scamWord === 1 || riskyTld === 1 || dotCount > 4 || urlLen > 75) {
            prediction = 1; // Classify as Phishing
        } else {
            prediction = 0; // Classify as Safe
        }
    }

    const uiMetrics = {
        urlLength: features["url_length"] ?? url.length,
        dotCount: features["dot_count"] ?? 0,
        isHttps: (features["is_https"] ?? 1) === 1
    };

    return {
        prediction: prediction,
        metrics: uiMetrics,
        status: "success"
    };
}
