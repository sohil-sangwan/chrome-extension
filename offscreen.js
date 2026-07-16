// ... existing code ...
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
                // combination (e.g. Unencrypted HTTP link combined with a scam keyword/risky TLD).
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
// ... existing code ...
