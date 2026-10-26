const urlInput = document.getElementById("urlInput");
const analyzeButton = document.getElementById("analyzeButton");
const resultSection = document.getElementById("resultSection");
const errorMessage = document.getElementById("errorMessage");
const verdictText = document.getElementById("verdictText");
const verdictDescription = document.getElementById("verdictDescription");
const verdictIcon = document.getElementById("verdictIcon");
const riskScore = document.getElementById("riskScore");
const riskBar = document.getElementById("riskBar");
const riskLevel = document.getElementById("riskLevel");
const probability = document.getElementById("probability");
const analyzedUrl = document.getElementById("analyzedUrl");
const securityStatus = document.getElementById("securityStatus");
const resultTime = document.getElementById("resultTime");

analyzeButton.addEventListener("click", analyzeURL);
urlInput.addEventListener("keydown", event => {
    if (event.key === "Enter") analyzeURL();
});

async function analyzeURL() {
    const url = urlInput.value.trim();
    errorMessage.style.display = "none";
    if (!url) {
        errorMessage.textContent = "Please enter a URL to analyze.";
        errorMessage.style.display = "block";
        return;
    }

    analyzeButton.disabled = true;
    analyzeButton.querySelector("span").textContent = "ANALYZING...";
    const clientStarted = performance.now();

    try {
        const response = await fetch("http://127.0.0.1:5000/api/predict", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({url})
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Unable to analyze URL.");
        data.client_response_time_ms = Number((performance.now() - clientStarted).toFixed(2));
        displayResult(data);
    } catch (error) {
        errorMessage.textContent = error.message || "Unable to connect to the analysis server.";
        errorMessage.style.display = "block";
    } finally {
        analyzeButton.disabled = false;
        analyzeButton.querySelector("span").textContent = "ANALYZE URL";
    }
}

function displayResult(data) {
    resultSection.classList.remove("hidden");
    const score = Number(data.risk_score || 0);
    const isPhishing = String(data.prediction).toLowerCase() === "phishing";
    const intel = data.threat_intelligence || {};
    const indicators = Array.isArray(intel.indicators) ? intel.indicators : [];
    const evidence = data.evidence_assessment || {};
    const performanceData = data.performance || {};

    verdictText.textContent = isPhishing ? "PHISHING DETECTED" : "LEGITIMATE";
    verdictDescription.textContent = isPhishing
        ? "The machine-learning model identifies characteristics associated with phishing."
        : "The model did not classify this URL as phishing. This is not a guarantee of safety.";
    verdictIcon.textContent = isPhishing ? "!" : "✓";
    riskScore.textContent = score.toFixed(2);
    riskLevel.textContent = score >= 70 ? "HIGH RISK" : score >= 30 ? "MEDIUM RISK" : "LOW RISK";
    riskLevel.style.color = score >= 70 ? "var(--danger)" : score >= 30 ? "#f0b84b" : "var(--success)";
    riskBar.style.width = Math.min(Math.max(score, 0), 100) + "%";
    riskBar.style.background = score >= 70 ? "var(--danger)" : score >= 30 ? "#f0b84b" : "var(--success)";
    probability.textContent = Number(data.phishing_probability || 0).toFixed(2);
    analyzedUrl.textContent = data.url || urlInput.value.trim();

    const dnsText = intel.dns_resolved ? "Resolved" : "Not resolved";
    const httpsText = intel.https ? "Enabled" : "Not enabled";
    const indicatorMarkup = indicators.length
        ? indicators.map(item => '<li>' + escapeHTML(item) + '</li>').join("")
        : "<li>No heuristic warning indicators were detected.</li>";

    securityStatus.innerHTML = `
        <div class="aptis-evidence-panel">
            <div class="aptis-evidence-heading">EVIDENCE & HOST CHECKS</div>
            <div class="aptis-evidence-grid">
                <div><span>Hostname</span><strong>${escapeHTML(intel.hostname || "Unavailable")}</strong></div>
                <div><span>Resolved IP</span><strong>${escapeHTML(intel.ip_address || "Not resolved")}</strong></div>
                <div><span>DNS status</span><strong>${dnsText}</strong></div>
                <div><span>HTTPS</span><strong>${httpsText}</strong></div>
                <div><span>Heuristic score</span><strong>${Number(intel.threat_score || 0)}/100</strong></div>
                <div><span>Indicators found</span><strong>${indicators.length}</strong></div>
            </div>
            <div class="aptis-evidence-heading">OBSERVED INDICATORS</div>
            <ul class="aptis-indicators">${indicatorMarkup}</ul>
            <div class="aptis-review-box ${evidence.manual_review_recommended ? "review-needed" : "signals-agree"}">
                <strong>${escapeHTML(evidence.status || "Evidence assessment unavailable")}</strong>
                <p>${escapeHTML(evidence.reason || "No explanation returned.")}</p>
                <small>Heuristic checks are supporting signals, not a confirmed threat-intelligence blacklist verdict.</small>
            </div>
            <div class="aptis-performance">
                <div><span>Server processing</span><strong>${Number(performanceData.response_time_ms || 0).toFixed(2)} ms</strong></div>
                <div><span>Client round trip</span><strong>${Number(data.client_response_time_ms || 0).toFixed(2)} ms</strong></div>
            </div>
        </div>`;

    resultTime.textContent = new Date().toLocaleString();
    resultSection.scrollIntoView({behavior: "smooth", block: "start"});
}

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[char]);
}
