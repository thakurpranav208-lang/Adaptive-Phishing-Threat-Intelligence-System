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


urlInput.addEventListener("keydown", function(event) {

    if (event.key === "Enter") {
        analyzeURL();
    }

});


async function analyzeURL() {

    const url = urlInput.value.trim();

    errorMessage.style.display = "none";


    if (!url) {

        errorMessage.textContent =
            "Please enter a URL to analyze.";

        errorMessage.style.display = "block";

        return;
    }


    analyzeButton.disabled = true;

    analyzeButton.querySelector("span").textContent =
        "ANALYZING...";


    try {

        const response = await fetch(
            "http://127.0.0.1:5000/api/predict",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    url: url
                })
            }
        );


        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Unable to analyze URL."
            );

        }


        displayResult(data);


    } catch (error) {

        errorMessage.textContent =
            error.message ||
            "Unable to connect to the analysis server.";

        errorMessage.style.display = "block";

    } finally {

        analyzeButton.disabled = false;

        analyzeButton.querySelector("span").textContent =
            "ANALYZE URL";

    }

}


function displayResult(data) {

    resultSection.classList.remove("hidden");


    const isPhishing =
        data.prediction.toLowerCase() === "phishing";


    verdictText.textContent =
        isPhishing
            ? "PHISHING DETECTED"
            : "LEGITIMATE";


    verdictDescription.textContent =
        isPhishing
            ? "This URL shows characteristics associated with phishing activity."
            : "This URL appears to be legitimate based on the analyzed characteristics.";


    verdictIcon.textContent =
        isPhishing
            ? "!"
            : "✓";


    const score =
        Number(data.risk_score);


    const phishingProbability =
        Number(data.phishing_probability);


    riskScore.textContent =
        score.toFixed(2);


    probability.textContent =
        phishingProbability.toFixed(2);


    riskBar.style.width =
        Math.min(score, 100) + "%";


    analyzedUrl.textContent =
        data.url;


    /*
     * -----------------------------------------
     * THREAT INTELLIGENCE DATA
     * -----------------------------------------
     */

    const threatIntel =
        data.threat_intelligence || {};


    const hostname =
        threatIntel.hostname || "Unavailable";


    const ipAddress =
        threatIntel.ip_address || "Not resolved";


    const dnsResolved =
        threatIntel.dns_resolved;


    const httpsEnabled =
        threatIntel.https;


    const urlLength =
        threatIntel.url_length || 0;


    const threatScore =
        Number(threatIntel.threat_score || 0);


    const indicators =
        threatIntel.indicators || [];


    /*
     * -----------------------------------------
     * RISK LEVEL
     * -----------------------------------------
     */

    if (score >= 70) {

        riskLevel.textContent =
            "HIGH RISK";

        riskLevel.style.color =
            "var(--danger)";

        verdictText.style.color =
            "var(--danger)";

        verdictIcon.style.color =
            "var(--danger)";

        verdictIcon.style.background =
            "rgba(255, 85, 119, 0.1)";

        riskBar.style.background =
            "var(--danger)";


    } else if (score >= 30) {

        riskLevel.textContent =
            "MEDIUM RISK";

        riskLevel.style.color =
            "#f0b84b";

        verdictText.style.color =
            "#f0b84b";

        verdictIcon.textContent =
            "⚠";

        verdictIcon.style.color =
            "#f0b84b";

        verdictIcon.style.background =
            "rgba(240, 184, 75, 0.1)";

        riskBar.style.background =
            "#f0b84b";


    } else {

        riskLevel.textContent =
            "LOW RISK";

        riskLevel.style.color =
            "var(--success)";

        verdictText.style.color =
            "var(--success)";

        verdictIcon.textContent =
            "✓";

        verdictIcon.style.color =
            "var(--success)";

        verdictIcon.style.background =
            "rgba(46, 230, 166, 0.1)";

        riskBar.style.background =
            "var(--success)";

    }


    /*
     * -----------------------------------------
     * THREAT INTELLIGENCE STATUS
     * -----------------------------------------
     */

    const dnsText =
        dnsResolved
            ? "Resolved"
            : "Not Resolved";


    const dnsColor =
        dnsResolved
            ? "var(--success)"
            : "var(--danger)";


    const httpsText =
        httpsEnabled
            ? "Enabled"
            : "Not Enabled";


    const httpsColor =
        httpsEnabled
            ? "var(--success)"
            : "var(--danger)";


    /*
     * Create indicator list
     */

    let indicatorHTML = "";


    if (indicators.length > 0) {

        indicatorHTML = indicators
            .map(function(indicator) {

                return `
                    <div style="
                        display: flex;
                        align-items: center;
                        gap: 10px;
                        margin-top: 8px;
                        color: #ff5577;
                        font-size: 14px;
                    ">
                        <span>⚠</span>
                        <span>${indicator}</span>
                    </div>
                `;

            })
            .join("");


    } else {

        indicatorHTML = `
            <div style="
                margin-top: 8px;
                color: var(--success);
                font-size: 14px;
            ">
                ✓ No suspicious indicators detected
            </div>
        `;

    }


    /*
     * -----------------------------------------
     * SECURITY STATUS CARD
     * -----------------------------------------
     */

    securityStatus.innerHTML = `

        <div style="
            width: 100%;
        ">

            <div style="
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 18px;
            ">

                <span style="
                    color: ${isPhishing
                        ? "var(--danger)"
                        : "var(--success)"
                    };
                    font-size: 24px;
                ">
                    ${isPhishing ? "!" : "✓"}
                </span>

                <div>

                    <strong style="
                        color: ${isPhishing
                            ? "var(--danger)"
                            : "var(--success)"
                        };
                        font-size: 18px;
                    ">
                        ${isPhishing
                            ? "High Risk"
                            : "Low Risk"
                        }
                    </strong>

                    <p style="
                        margin: 4px 0 0 0;
                    ">
                        ${isPhishing
                            ? "The URL has characteristics strongly associated with phishing activity."
                            : "No significant phishing indicators detected."
                        }
                    </p>

                </div>

            </div>


            <div style="
                border-top: 1px solid rgba(255,255,255,0.08);
                padding-top: 18px;
            ">

                <div style="
                    color: #18d9ff;
                    font-size: 13px;
                    font-weight: 700;
                    letter-spacing: 1.5px;
                    margin-bottom: 14px;
                ">
                    THREAT INTELLIGENCE
                </div>


                <div style="
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 12px;
                    margin-bottom: 16px;
                ">

                    <div style="
                        padding: 12px;
                        background: rgba(255,255,255,0.03);
                        border-radius: 8px;
                    ">

                        <div style="
                            font-size: 12px;
                            opacity: 0.6;
                            margin-bottom: 5px;
                        ">
                            DNS STATUS
                        </div>

                        <strong style="
                            color: ${dnsColor};
                        ">
                            ${dnsText}
                        </strong>

                    </div>


                    <div style="
                        padding: 12px;
                        background: rgba(255,255,255,0.03);
                        border-radius: 8px;
                    ">

                        <div style="
                            font-size: 12px;
                            opacity: 0.6;
                            margin-bottom: 5px;
                        ">
                            HTTPS
                        </div>

                        <strong style="
                            color: ${httpsColor};
                        ">
                            ${httpsText}
                        </strong>

                    </div>


                    <div style="
                        padding: 12px;
                        background: rgba(255,255,255,0.03);
                        border-radius: 8px;
                    ">

                        <div style="
                            font-size: 12px;
                            opacity: 0.6;
                            margin-bottom: 5px;
                        ">
                            URL LENGTH
                        </div>

                        <strong>
                            ${urlLength}
                        </strong>

                    </div>


                    <div style="
                        padding: 12px;
                        background: rgba(255,255,255,0.03);
                        border-radius: 8px;
                    ">

                        <div style="
                            font-size: 12px;
                            opacity: 0.6;
                            margin-bottom: 5px;
                        ">
                            TI SCORE
                        </div>

                        <strong style="
                            color: ${
                                threatScore >= 50
                                    ? "var(--danger)"
                                    : threatScore >= 30
                                        ? "#f0b84b"
                                        : "var(--success)"
                            };
                        ">
                            ${threatScore}/100
                        </strong>

                    </div>

                </div>


                <div style="
                    font-size: 12px;
                    opacity: 0.6;
                    margin-bottom: 4px;
                ">
                    HOSTNAME
                </div>

                <div style="
                    font-size: 14px;
                    word-break: break-all;
                    margin-bottom: 14px;
                ">
                    ${hostname}
                </div>


                <div style="
                    font-size: 12px;
                    opacity: 0.6;
                    margin-bottom: 4px;
                ">
                    IP ADDRESS
                </div>

                <div style="
                    font-size: 14px;
                    margin-bottom: 14px;
                ">
                    ${ipAddress}
                </div>


                <div style="
                    font-size: 12px;
                    opacity: 0.6;
                    margin-bottom: 4px;
                ">
                    DETECTED INDICATORS
                </div>

                ${indicatorHTML}

            </div>

        </div>

    `;


    resultTime.textContent =
        "Analyzed " +
        new Date().toLocaleTimeString();


    resultSection.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

}