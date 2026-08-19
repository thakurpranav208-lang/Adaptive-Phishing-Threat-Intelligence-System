import os
import re
import joblib
import numpy as np
import pandas as pd
import tldextract

from urllib.parse import urlparse


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)


MODEL_PATH = os.path.join(
    BASE_DIR,
    "data",
    "models",
    "final_model.pkl"
)


SCALER_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "scaler.pkl"
)


model = joblib.load(MODEL_PATH)

scaler = joblib.load(SCALER_PATH)


FEATURE_NAMES = [
    "url_len",
    "dom_len",
    "is_ip",
    "tld_len",
    "subdom_cnt",
    "letter_cnt",
    "digit_cnt",
    "special_cnt",
    "eq_cnt",
    "qm_cnt",
    "amp_cnt",
    "dot_cnt",
    "dash_cnt",
    "under_cnt",
    "letter_ratio",
    "digit_ratio",
    "spec_ratio",
    "is_https",
    "slash_cnt",
    "entropy",
    "path_len",
    "query_len"
]


def extract_features(url):

    parsed_url = urlparse(url)

    domain = parsed_url.netloc

    path = parsed_url.path

    query = parsed_url.query

    url_length = len(url)


    # Remove port number if present
    domain_for_check = domain.split(":")[0]


    # Check whether domain is an IP address
    is_ip = int(
        bool(
            re.fullmatch(
                r"(?:\d{1,3}\.){3}\d{1,3}",
                domain_for_check
            )
        )
    )


    # Extract subdomain, registered domain and TLD correctly
    extracted = tldextract.extract(domain_for_check)


    registered_domain = ""

    if extracted.domain and extracted.suffix:

        registered_domain = (
            extracted.domain
            + "."
            + extracted.suffix
        )

    elif extracted.domain:

        registered_domain = extracted.domain


    # Domain length
    domain_length = len(registered_domain)


    # TLD
    tld = extracted.suffix

    tld_length = len(tld)


    # Number of subdomains
    subdomain_count = (
        len(extracted.subdomain.split("."))
        if extracted.subdomain
        else 0
    )


    # Character counts
    letter_count = sum(
        c.isalpha()
        for c in url
    )


    digit_count = sum(
        c.isdigit()
        for c in url
    )


    special_count = sum(
        not c.isalnum()
        for c in url
    )


    eq_count = url.count("=")

    qm_count = url.count("?")

    amp_count = url.count("&")

    dot_count = url.count(".")

    dash_count = url.count("-")

    under_count = url.count("_")


    # Ratios
    letter_ratio = (
        letter_count / url_length
        if url_length
        else 0
    )


    digit_ratio = (
        digit_count / url_length
        if url_length
        else 0
    )


    special_ratio = (
        special_count / url_length
        if url_length
        else 0
    )


    # HTTPS
    is_https = int(
        parsed_url.scheme.lower() == "https"
    )


    # Slash count
    slash_count = url.count("/")


    # Entropy
    if url:

        character_counts = (
            pd.Series(list(url))
            .value_counts()
        )

        probabilities = (
            character_counts / len(url)
        )

        entropy = -sum(
            probabilities
            * np.log2(probabilities)
        )

    else:

        entropy = 0


    # Path and query lengths
    path_length = len(path)

    query_length = len(query)


    # Create feature list
    features = [
        url_length,
        domain_length,
        is_ip,
        tld_length,
        subdomain_count,
        letter_count,
        digit_count,
        special_count,
        eq_count,
        qm_count,
        amp_count,
        dot_count,
        dash_count,
        under_count,
        letter_ratio,
        digit_ratio,
        special_ratio,
        is_https,
        slash_count,
        entropy,
        path_length,
        query_length
    ]


    return pd.DataFrame(
        [features],
        columns=FEATURE_NAMES
    )


def predict_url(url):

    features = extract_features(url)


    features_scaled = scaler.transform(
        features
    )


    prediction = model.predict(
        features_scaled
    )[0]


    probabilities = model.predict_proba(
        features_scaled
    )[0]


    phishing_probability = float(
        probabilities[1]
    )


    risk_score = round(
        phishing_probability * 100,
        2
    )


    verdict = (
        "Phishing"
        if prediction == 1
        else "Legitimate"
    )


    return {
        "url": url,
        "prediction": verdict,
        "phishing_probability": round(
            phishing_probability * 100,
            2
        ),
        "risk_score": risk_score
    }