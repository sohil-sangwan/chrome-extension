// Function to safely create or find the hidden AI window
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
        const urlObj = new URL(urlString);
        let hostname = urlObj.hostname;
        // Strip www. if present
        if (hostname.startsWith("www.")) {
            hostname = hostname.substring(4);
        }
        // Extract primary domain segment before the TLD suffix
        const parts = hostname.split('.');
        if (parts.length >= 2) {
            return parts[parts.length - 2];
        }
        return hostname;
    } catch (e) {
        return "";
    }
}

function extractTldSuffix(urlString) {
    try {
        const urlObj = new URL(urlString);
        const parts = urlObj.hostname.split('.');
        if (parts.length > 1) {
            return parts[parts.length - 1];
        }
        return "";
    } catch (e) {
        return "";
    }
}

// Synchronous tab updates event listener registration
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && !tab.url.startsWith('chrome://')) {
        console.log(`[*] Running real-time evaluation loop for: ${tab.url}`);
        
        try {
            await setupOffscreenEngine();

            const urlString = tab.url;
            const cleanUrlLower = urlString.toLowerCase();
            const domainName = extractDomainName(urlString);
            const tldSuffix = extractTldSuffix(urlString);

            // 1. Calculate features exactly like the Python pipeline
            const urlLength = parseFloat(urlString.length);
            const dotCount = parseFloat((urlString.match(/\./g) || []).length);
            const isHttps = urlString.startsWith('https://') ? 1.0 : 0.0;
            const domainEntropy = calculateEntropy(domainName);
            
            const riskyTlds = ['xyz', 'tk', 'ml', 'cf', 'gq', 'top', 'cc'];
            const isRiskyTld = riskyTlds.includes(tldSuffix) ? 1.0 : 0.0;
            
            const scamKeywords = ['kyc', 'verification', 'blocked', 'refund', 'login', 'paytm', 'irctc', 'sbi'];
            const containsScamKeyword = scamKeywords.some(kw => cleanUrlLower.includes(kw)) ? 1.0 : 0.0;

            // 2. CRITICAL: Arrange array in exact alphabetical matrix order expected by your ONNX graph
            const liveInputFeatures = [
                containsScamKeyword,  // Feature 1
                domainEntropy,         // Feature 2
                dotCount,              // Feature 3
                isHttps,               // Feature 4
                isRiskyTld,            // Feature 5
                urlLength              // Feature 6
            ];
            
            console.log(`[*] Calculated Matrix: [Keywords: ${containsScamKeyword}, Entropy: ${domainEntropy}, Dots: ${dotCount}, HTTPS: ${isHttps}, RiskyTLD: ${isRiskyTld}, Len: ${urlLength}]`);

            // Pass the verified matrix to the hidden AI engine
            chrome.runtime.sendMessage({
                target: 'offscreen-ai',
                data: liveInputFeatures
            }, (prediction) => {
                if (chrome.runtime.lastError) return;
                
                if (prediction !== undefined) {
                    console.log(`[+] Prediction Output Matrix: ${prediction}`);
                    console.log(`[+] ByteShield Status: ${prediction === 1 ? "⚠️ PHISHING" : "✅ SAFE"}`);
                }
            });

        } catch (err) {
            console.error("[-] Background routing error:", err);
        }
    }
});