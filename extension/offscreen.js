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

// Initialize the local ONNX engine within the unrestricted DOM environment
async function getModelSession() {
    if (estimationSession) return estimationSession;

    try {
        ort.env.wasm.wasmPaths = {
            'ort-wasm.wasm': chrome.runtime.getURL('ort-wasm.wasm'),
            'ort-wasm-simd.wasm': chrome.runtime.getURL('ort-wasm-simd.wasm'),
            'ort-wasm-simd-threaded.wasm': chrome.runtime.getURL('ort-wasm-simd-threaded.wasm'),
            'ort-wasm-simd-threaded.jsep.mjs': chrome.runtime.getURL('ort-wasm-simd-threaded.jsep.mjs'),
            'ort-wasm-simd-threaded.jsep.wasm': chrome.runtime.getURL('ort-wasm-simd-threaded.jsep.wasm')
        };

        console.log("[*] Offscreen compiling WebAssembly engine binary...");
        estimationSession = await ort.InferenceSession.create(
            chrome.runtime.getURL('byteshield_model.onnx'),
            { executionProviders: ['wasm'] }
        );
        console.log("[+] Offscreen ONNX structural weights loaded successfully.");
        return estimationSession;
    } catch (err) {
        console.error("[-] Offscreen model initialization failed:", err);
        return null;
    }
}

// Pre-warm the WebAssembly model immediately when the offscreen document boots up
getModelSession();

// Listen for processing orders sent from background.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action !== "RUN_INFERENCE") return false;

    const { url, features } = message.payload;
    if (!features) {
        sendResponse({ prediction: 0, metrics: null, status: "error" });
        return false;
    }

    (async () => {
        try {
            // Ensure session is active
            const session = await getModelSession();
            let prediction = 0;
            let inferenceSuccess = false;

            // 1. Arrange the features in strict alphabetical index order
            const sortedArray = ALPHABETICAL_FEATURES.map(key => {
                const val = features[key];
                return val !== undefined ? parseFloat(val) : 0.0;
            });

            console.log(`[*] Calibrated alphabetical feature vector: [${sortedArray.join(", ")}]`);

            if (session) {
                // 2. Wrap inputs into an ONNX tensor representing a single evaluation record (1 x N)
                const inputTensor = new ort.Tensor("float32", Float32Array.from(sortedArray), [1, sortedArray.length]);
                
                // 3. Run model calculation
                const feeds = { [session.inputNames[0]]: inputTensor };
                const results = await session.run(feeds);

                // 4. Read class labels outputs
                const labelOutput = results[session.outputNames[0]];
                if (labelOutput && labelOutput.data) {
                    prediction = Number(labelOutput.data[0]);
                    inferenceSuccess = true;
                    console.log(`[+] ONNX model prediction completed. Output: ${prediction}`);
                }
            }

            // ====================================================================
            // HIGH-PRECISION OVERRULE GATE
            // ====================================================================
            if (inferenceSuccess && prediction === 1) {
                const scamWord = features["contains_scam_keyword"] ?? 0;
                const riskyTld = features["is_risky_tld"] ?? 0;
                const isHttps = features["is_https"] ?? 1;
                const entropy = features["domain_entropy"] ?? 0;

                // Overrule model's prediction of "Phishing" to "Safe" if:
                // It is a secure HTTPS page, has no obvious scam keywords, no risky TLD,
                // and has normal domain complexity. This curbs random model variations!
                if (isHttps === 1 && scamWord === 0 && riskyTld === 0 && entropy < 4.0) {
                    console.log("[🛡️ Overrule Gate] Model predicted Phishing, but safety heuristics corrected to Safe (0).");
                    prediction = 0;
                }
            }

            // ====================================================================
            // CONSERVATIVE FALLBACK BOUNDARY (Triggered if ONNX initialization fails)
            // ====================================================================
            if (!inferenceSuccess) {
                const scamWord = features["contains_scam_keyword"] ?? 0;
                const riskyTld = features["is_risky_tld"] ?? 0;
                const urlLen = features["url_length"] ?? 0;
                const dotCount = features["dot_count"] ?? 0;
                const isHttps = features["is_https"] ?? 1;

                // STRICT FAIL-OPEN POLICY: 
                // If the model is slow to load/compile, we default to SAFE (0) 
                // for secure HTTPS pages unless there is an absolute high-confidence 
                // combination (e.g., Unencrypted HTTP link combined with a scam keyword/risky TLD).
                // This completely prevents false blocks on slow SSO/OAuth login redirects.
                if (isHttps === 0 && (scamWord === 1 || riskyTld === 1)) {
                    prediction = 1;
                } else if (scamWord === 1 && dotCount > 3) {
                    prediction = 1; // High confidence subdomain spoof trickery
                } else {
                    prediction = 0; // Safe: Fail-Open to preserve smooth user browsing
                }
            }
            // ====================================================================

            // Map standard keys back to display formats for popup.js and cache matching
            const uiMetrics = {
                urlLength: features["url_length"] ?? url.length,
                dotCount: features["dot_count"] ?? 0,
                isHttps: (features["is_https"] ?? 1) === 1
            };

            // Return calculated prediction and indicators to background.js
            sendResponse({
                prediction: prediction,
                metrics: uiMetrics,
                status: "success"
            });

        } catch (err) {
            console.error("[-] Offscreen runtime execution exception:", err);
            sendResponse({ prediction: 0, metrics: null, status: "error" });
        }
    })();

    return true; // Keep the runtime message channel open for the async response
});
