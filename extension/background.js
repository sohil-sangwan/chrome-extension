// Lock promise to prevent concurrent offscreen document creation race conditions
let creatingOffscreen = null;

// Global memory cache storing prediction outputs mapped to active browser tabs
const predictionCache = {};

// High-Authority Local Whitelist to prevent false-positives on safe domains
const SAFE_WHITELIST = [
    "google.com",
    "sarkariresult.com",
    "wikipedia.org",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "youtube.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "yahoo.com",
    "netflix.com"
];

// Checks if a URL belongs to a high-authority whitelisted domain
function isWhitelisted(urlStr) {
    try {
        const parsed = new URL(urlStr);
        const hostname = parsed.hostname.toLowerCase();
        const cleanHost = hostname.startsWith("www.") ? hostname.substring(4) : hostname;
        return SAFE_WHITELIST.some(domain => cleanHost === domain || cleanHost.endsWith("." + domain));
    } catch {
        return false;
    }
}

// Function to safely create or find the hidden AI window context
async function setupOffscreenEngine() {
    if (creatingOffscreen) {
        await creatingOffscreen;
        return;
    }

    try {
        const existingContexts = await chrome.runtime.getContexts({
            contextTypes: ['OFFSCREEN_DOCUMENT']
        });

        if (existingContexts.length > 0) return;

        creatingOffscreen = chrome.offscreen.createDocument({
            url: 'offscreen.html',
            reasons: ['WORKERS'], // Informs Chrome we are compiling worker matrices
            justification: 'Executing local ONNX machine learning model inference.'
        });

        await creatingOffscreen;
        console.log("[+] Secure Offscreen AI Engine Room Initialized.");
    } catch (err) {
        if (err.message && err.message.includes("Only a single offscreen document")) {
            console.log("[*] Offscreen document already initialized concurrently.");
        } else {
            console.error("[-] Offscreen document creation failed:", err);
        }
    } finally {
        creatingOffscreen = null;
    }
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

function storePredictionResult(tabId, predictionVerdict, featureMetrics) {
    predictionCache[tabId] = {
        prediction: predictionVerdict, // 0 = Safe, 1 = Phishing
        metrics: featureMetrics,       // { urlLength, dotCount, isHttps }
        timestamp: Date.now()
    };
    console.log(`[+] Prediction Cached for tab ${tabId}:`, predictionCache[tabId]);
}

function handlePhishingVerdict(tabId, maliciousUrl) {
    const warningPageUrl = chrome.runtime.getURL(`warning.html`) + `?url=${encodeURIComponent(maliciousUrl)}`;
    chrome.tabs.update(tabId, { url: warningPageUrl });
    console.log(`[⚠️] Intercepted phishing navigation on tab ${tabId}. Redirecting to safety screen.`);
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Only execute when the tab starts loading a standard web address
    if (changeInfo.status === 'loading' && tab.url && tab.url.startsWith('http')) {
        // Avoid intercepting our own warning page to prevent infinite redirects
        if (tab.url.includes(chrome.runtime.id) && tab.url.includes('warning.html')) {
            return;
        }

        console.log(`[*] Running real-time evaluation loop for: ${tab.url}`);

        // OPTIMIZATION: Instantly whitelist safe authority domains without executing model analysis
        if (isWhitelisted(tab.url)) {
            console.log(`[✅] High-Authority whitelist hit. Instantly whitelisting: ${tab.url}`);
            const defaultMetrics = {
                urlLength: tab.url.length,
                dotCount: (tab.url.match(/\./g) || []).length,
                isHttps: tab.url.startsWith('https://')
            };
            storePredictionResult(tabId, 0, defaultMetrics);
            return;
        }

        try {
            // 1. Ensure the Offscreen DOM Document is awake and initialized safely
            await setupOffscreenEngine();

            // 2. Extract Javascript features from the current URL
            const extractedFeatures = extractFeatures(tab.url);
            console.log(`[*] Calculated Matrix: [Keywords: ${extractedFeatures.contains_scam_keyword}, Entropy: ${extractedFeatures.domain_entropy}, Dots: ${extractedFeatures.dot_count}, HTTPS: ${extractedFeatures.is_https}, RiskyTLD: ${extractedFeatures.is_risky_tld}, Len: ${extractedFeatures.url_length}]`);

            // 3. Dispatch the payload to the offscreen worker for execution
            chrome.runtime.sendMessage({
                action: "RUN_INFERENCE",
                payload: {
                    url: tab.url,
                    features: extractedFeatures
                }
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("[-] Message sending failed or timed out:", chrome.runtime.lastError);
                    return;
                }
                
                if (response && response.status === "success") {
                    const { prediction, metrics } = response;
                    
                    console.log(`[+] Prediction Output Score: ${prediction}`);
                    console.log(`[+] ByteShield Status: ${prediction === 1 ? "⚠️ PHISHING/UNSAFE" : "✅ SAFE"}`);
                    
                    storePredictionResult(tabId, prediction, metrics);
                    
                    if (prediction === 1) {
                        handlePhishingVerdict(tabId, tab.url);
                    }
                } else {
                    console.error("[-] Offscreen engine returned an invalid/failed response schema:", response);
                }
            });

        } catch (err) {
            console.error("[-] Background routing error:", err);
        }
    }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "GET_LATEST_PREDICTION") {
        const data = predictionCache[message.tabId] || null;
        sendResponse({ data: data });
    }
    return true; 
});

chrome.tabs.onRemoved.addListener((tabId) => {
    if (predictionCache[tabId]) {
        delete predictionCache[tabId];
    }
});
