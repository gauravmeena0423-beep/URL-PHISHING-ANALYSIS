chrome.runtime.onInstalled.addListener(() => {
    // Chrome me right-click menu banana
    chrome.contextMenus.create({
        id: "scan_with_phishguard",
        title: "🛡️ Scan Link with PhishGuard",
        contexts: ["link"]
    });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "scan_with_phishguard") {
        // Future update: Yahan se bhi direct API call lag sakti hai
        console.log("User right-clicked on this link:", info.linkUrl);
        // Abhi ke liye hum user ko alert kar rahe hain
        chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => alert("Link copied to PhishGuard! Open extension to scan.")
        });
    }
});