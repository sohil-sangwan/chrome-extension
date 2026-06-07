chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "inject_warning") {
    showPhishingBanner(request.reason);
  }
});

function showPhishingBanner(reason) {
  // Prevent duplicate banners from cluttering the viewport
  if (document.getElementById("byteshield-alert-banner")) return;

  const banner = document.createElement("div");
  banner.id = "byteshield-alert-banner";
  banner.innerHTML = `
    <div style="background: #d93025; color: white; padding: 15px; font-family: sans-serif; position: fixed; top: 0; left: 0; width: 100%; z-index: 2147483647; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 6px rgba(0,0,0,0.2);">
      <span>⚠️ <strong>ByteShield Warning:</strong> This URL matches patterns of a high-risk phishing site (${reason}). Proceed with caution!</span>
      <button id="close-byteshield-banner" style="background: white; color: #d93025; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-weight: bold;">Dismiss</button>
    </div>
  `;
  document.body.appendChild(banner);

  document.getElementById("close-byteshield-banner").addEventListener("click", () => {
    banner.remove();
  });
}