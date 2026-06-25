// Function to safely create or find the hidden AI window context
async function setupOffscreenEngine() {
    const existingContexts = await chrome.runtime.getContexts({
        contextTypes: ['OFFSCREEN_DOCUMENT']
    });

    if (existingContexts.length > 0) return;

    // Open our hidden HTML math engine room natively
    await chrome.offscreen.createDocument({
        url: 'offscreen.html',
        reasons: ['WORKERS'], // Informs Chrome we are handling worker matrices
        justification: 'Executing local ONNX machine learning model inference.'
    });
    console.log("[+] Secure Offscreen AI Engine Room Initialized.");
}

// =====================================================================
// NATIVE JAVASCRIPT FEATURE ENGINEERING LAYER (Mirrors Python Code)
// =====================================================================
function calculateEntropy(text) {
    if (!text) return 0;
    const len = text.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
        const c = text[i];
        frequencies[c] = (frequencies[c] || 0) + 1;
    }
    let entropy = 0;
    for (const c in frequencies) {
        const p = frequencies[c] / len;
        entropy -= p * Math.log2(p);
    }
    return parseFloat(entropy.toFixed(2));
}

function extractDomainName(urlString) {
    try {
        const parsed = new URL(urlString);
        return parsed.hostname;
    } catch {
        return "";
    }
}

function extractDomainExtension(domain) {
    const parts = domain.split('.');
    return parts.length > 1 ? `.${parts[parts.length - 1]}` : "";
}

function extractFeatures(url) {
    const domain = extractDomainName(url);
    const ext = extractDomainExtension(domain);
    
    const features = {};
    features['url_length'] = url.length;
    features['dot_count'] = (url.match(/\./g) || []).length;
    features['is_https'] = url.startsWith('https://') ? 1 : 0;
    features['domain_entropy'] = calculateEntropy(domain);
    
    const riskyTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.cc', '.xyz', '.live', '.click'];
    features['is_risky_tld'] = riskyTlds.includes(ext) ? 1 : 0;
    
    const scamKeywords = ['kyc', 'verification', 'blocked', 'refund', 'login', 'paytm', 'irctc', 'sbi', 'secure', 'claim', 'cashback', 'allegrolokalnie', 'oferta', 'free'];
    features['contains_scam_keyword'] = scamKeywords.some(kw => url.toLowerCase().includes(kw)) ? 1 : 0;
    
    return features;
}

// Memory cache holding prediction data for active browsing channels
const predictionCache = {};

// Helper to store predictions in cache so popup.js can fetch them
function storePredictionResult(tabId, predictionVerdict, featureMetrics) {
    predictionCache[tabId] = {
        prediction: predictionVerdict, // 0 = Safe, 1 = Phishing
        metrics: featureMetrics,       // { urlLength, dotCount, isHttps }
        timestamp: Date.now()
    };
    console.log(`[+] Cached prediction for tab ${tabId}:`, predictionCache[tabId]);
}

// Redirects a suspicious navigation to our local safety block page
function handlePhishingVerdict(tabId, maliciousUrl) {
    const warningPageUrl = chrome.runtime.getURL(`warning.html`) + `?url=${encodeURIComponent(maliciousUrl)}`;
    chrome.tabs.update(tabId, { url: warningPageUrl });
    console.log(`[⚠️] Intercepted phishing navigation on tab ${tabId}. Redirecting to safety screen.`);
}

// =====================================================================
// REAL-TIME TRAFFIC ROUTING LOOP
// =====================================================================
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Only execute when the tab starts loading a standard web address
    if (changeInfo.status === 'loading' && tab.url && tab.url.startsWith('http')) {
        // Avoid intercepting our own warning page to prevent infinite redirects
        if (tab.url.includes(chrome.runtime.id) && tab.url.includes('warning.html')) {
            return;
        }

        try {
            // 1. Ensure the Offscreen DOM Document is awake and initialized
            await setupOffscreenEngine();

            // 2. Extract Javascript features from the current URL
            const extractedFeatures = extractFeatures(tab.url);

            // 3. Dispatch the payload to the offscreen worker for execution
            chrome.runtime.sendMessage({
                action: "RUN_INFERENCE",
                payload: {
                    url: tab.url,
                    features: extractedFeatures
                }
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("[-] Message sending failed:", chrome.runtime.lastError);
                    return;
                }
                
                if (response && response.status === "success") {
                    const { prediction, metrics } = response;
                    
                    console.log(`[+] Prediction Output Score: ${prediction}`);
                    console.log(`[+] ByteShield Status: ${prediction === 1 ? "⚠️ PHISHING" : "✅ SAFE"}`);
                    
                    // CRUCIAL FIX: Store results inside the memory cache so popup.js can access it
                    storePredictionResult(tabId, prediction, metrics);
                    
                    // Active Intercept Safety Block
                    if (prediction === 1) {
                        handlePhishingVerdict(tabId, tab.url);
                    }
                } else {
                    console.error("[-] Offscreen engine returned an invalid response schema.");
                }
            });

        } catch (err) {
            console.error("[-] Background routing error:", err);
        }
    }
});

// Global Manifest V3 runtime message router for Popups
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "GET_LATEST_PREDICTION") {
        const data = predictionCache[message.tabId] || null;
        sendResponse({ data: data });
    }
    return true; // Keep message channel open for async handlers
});

// Clean up tab memory allocations when a user closes a browsing container
chrome.tabs.onRemoved.addListener((tabId) => {
    if (predictionCache[tabId]) {
        delete predictionCache[tabId];
    }
});
