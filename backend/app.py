from time import perf_counter

from flask import Flask, request, jsonify
from flask_cors import CORS

from predictor import predict_url
from threat_intelligence import analyze_url


app = Flask(__name__)
CORS(app)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "online", "service": "APTIS URL Threat Scanner"})


@app.route("/api/predict", methods=["POST"])
def predict():
    started_at = perf_counter()
    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = str(data["url"]).strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    # Ensure parsing works consistently for URLs entered without a scheme.
    if "://" not in url:
        url = "https://" + url

    try:
        ml_result = predict_url(url)
        threat_result = analyze_url(url)
    except Exception as exc:
        app.logger.exception("URL analysis failed")
        return jsonify({"error": "Unable to analyze this URL. Check the input and try again."}), 422

    score = float(ml_result.get("risk_score", 0))
    ti_score = float(threat_result.get("threat_score", 0))
    ml_phishing = str(ml_result.get("prediction", "")).lower() == "phishing"

    # Heuristic evidence reconciliation, not a definitive external reputation verdict.
    evidence_phishing = ti_score >= 45 or len(threat_result.get("indicators", [])) >= 3
    disagreement = ml_phishing != evidence_phishing
    insufficient_evidence = not threat_result.get("valid_url", False) or (
        not threat_result.get("dns_resolved", False) and not ml_phishing
    )

    if disagreement or insufficient_evidence:
        assessment = "Manual Review Recommended"
        assessment_reason = (
            "Machine-learning and URL/host indicators do not fully agree."
            if disagreement else
            "Some host evidence is unavailable, so this result should be reviewed."
        )
    elif ml_phishing and evidence_phishing:
        assessment = "High Risk — Signals Agree"
        assessment_reason = "The model verdict and multiple heuristic indicators point toward risk."
    else:
        assessment = "Lower Risk — Signals Agree"
        assessment_reason = "The model and available heuristic indicators do not show a strong phishing signal."

    elapsed_ms = round((perf_counter() - started_at) * 1000, 2)
    return jsonify({
        **ml_result,
        "url": url,
        "threat_intelligence": threat_result,
        "evidence_assessment": {
            "status": assessment,
            "reason": assessment_reason,
            "model_flagged_phishing": ml_phishing,
            "heuristic_evidence_flagged": evidence_phishing,
            "signals_disagree": disagreement,
            "manual_review_recommended": disagreement or insufficient_evidence
        },
        "performance": {
            "response_time_ms": elapsed_ms,
            "measurement": "server-side request processing; excludes browser rendering"
        }
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
