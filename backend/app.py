from flask import Flask, request, jsonify
from flask_cors import CORS

from predictor import predict_url
from threat_intelligence import analyze_url


app = Flask(__name__)

CORS(app)


@app.route("/api/predict", methods=["POST"])
def predict():

    data = request.get_json()

    if not data or "url" not in data:

        return jsonify({
            "error": "URL is required"
        }), 400


    url = data["url"].strip()


    if not url:

        return jsonify({
            "error": "URL cannot be empty"
        }), 400


    # Machine Learning analysis
    ml_result = predict_url(url)


    # Threat Intelligence analysis
    threat_result = analyze_url(url)


    # Combine both results
    result = {
        **ml_result,
        "threat_intelligence": threat_result
    }


    return jsonify(result)


if __name__ == "__main__":

    app.run(
        debug=True,
        port=5000
    )