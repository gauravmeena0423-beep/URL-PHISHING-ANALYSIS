document.addEventListener('DOMContentLoaded', async () => {
    const urlDisplay = document.getElementById('url-display');
    const scanBtn = document.getElementById('scan-btn');
    const resultBox = document.getElementById('result-box');
    const verdictText = document.getElementById('verdict');
    const scoreText = document.getElementById('score');

    // 1. Chrome se current tab ka URL maango
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    let currentUrl = tab.url;
    
    // URL ko chota karke dikhao UI pe
    urlDisplay.innerText = currentUrl.length > 50 ? currentUrl.substring(0, 50) + "..." : currentUrl;

    // 2. Scan Button Click Logic
    scanBtn.addEventListener('click', async () => {
        scanBtn.innerText = "Scanning AI Engine...";
        scanBtn.disabled = true;
        resultBox.style.display = "none";

        try {
            // Aapke FastAPI server par link bhejna
            let response = await fetch('http://localhost:8000/api/scan/check-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: currentUrl })
            });

            let data = await response.json();
            let threatInfo = data.threat_intelligence;

            // 3. UI Update karna result ke hisaab se
            resultBox.style.display = "block";
            scoreText.innerText = threatInfo.risk_score_percentage + "%";
            verdictText.innerText = threatInfo.verdict.toUpperCase();

            if (threatInfo.verdict === "Safe") {
                resultBox.className = "safe";
                verdictText.className = "text-safe";
                scoreText.className = "text-safe";
            } else {
                resultBox.className = "danger";
                verdictText.className = "text-danger";
                scoreText.className = "text-danger";
            }

        } catch (error) {
            alert("Backend Error! Is your Python Server running?");
        }

        scanBtn.innerText = "SCAN CURRENT PAGE";
        scanBtn.disabled = false;
    });
});