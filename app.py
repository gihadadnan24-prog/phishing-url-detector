import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs

import joblib
import pandas as pd
import streamlit as st


# ============================================================
# Page Configuration
# ============================================================

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# Feature Extraction
# ============================================================

def shannon_entropy(text):
    if not text:
        return 0.0

    probabilities = [
        text.count(char) / len(text)
        for char in set(text)
    ]

    return -sum(
        p * math.log2(p)
        for p in probabilities
        if p > 0
    )


def extract_enhanced_url_features(url):

    url = str(url).strip()

    parsed = urlparse(
        url if "://" in url else "http://" + url
    )

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    hostname_lower = hostname.lower()
    url_lower = url.lower()

    url_length = len(url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)
    fragment_length = len(fragment)

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    special_chars = sum(not c.isalnum() for c in url)

    digit_ratio = (
        digits / url_length
        if url_length else 0
    )

    letter_ratio = (
        letters / url_length
        if url_length else 0
    )

    special_ratio = (
        special_chars / url_length
        if url_length else 0
    )

    dot_count = url.count(".")
    hyphen_count = url.count("-")
    underscore_count = url.count("_")
    slash_count = url.count("/")
    question_count = url.count("?")
    equals_count = url.count("=")
    ampersand_count = url.count("&")
    at_count = url.count("@")
    percent_count = url.count("%")
    hash_count = url.count("#")

    hostname_digits = sum(
        c.isdigit()
        for c in hostname
    )

    hostname_hyphens = hostname.count("-")

    hostname_digit_ratio = (
        hostname_digits / hostname_length
        if hostname_length else 0
    )

    # Check whether hostname is an IP address
    is_ip = 0

    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
    except ValueError:
        is_ip = 0

    # Extract TLD
    if "." in hostname:
        tld = hostname.rsplit(".", 1)[-1].lower()
    else:
        tld = ""

    subdomain_count = max(
        hostname.count(".") - 1,
        0
    )

    # Path features
    path_slashes = path.count("/")
    path_hyphens = path.count("-")
    path_underscores = path.count("_")

    path_digits = sum(
        c.isdigit()
        for c in path
    )

    path_digit_ratio = (
        path_digits / path_length
        if path_length else 0
    )

    path_entropy = shannon_entropy(path)

    # Query features
    query_parameters = (
        len(parse_qs(query))
        if query else 0
    )

    query_digits = sum(
        c.isdigit()
        for c in query
    )

    query_digit_ratio = (
        query_digits / query_length
        if query_length else 0
    )

    # Obfuscation
    encoded_chars = len(
        re.findall(
            r"%[0-9A-Fa-f]{2}",
            url
        )
    )

    has_obfuscation = int(
        encoded_chars > 0
    )

    obfuscation_ratio = (
        encoded_chars / url_length
        if url_length else 0
    )

    # Repeated special characters
    repeated_special_chars = len(
        re.findall(
            r"([!@#$%^&*_\-+=?])\1+",
            url
        )
    )

    # Suspicious URL tokens
    suspicious_tokens = [
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "secure",
        "security",
        "account",
        "update",
        "password",
        "passwd",
        "bank",
        "banking",
        "billing",
        "payment",
        "confirm",
        "confirmation",
        "recover",
        "wallet",
        "support",
        "authenticate",
        "authorization",
        "credential",
        "reset"
    ]

    suspicious_token_count = sum(
        token in url_lower
        for token in suspicious_tokens
    )

    # Mixed alphanumeric tokens
    mixed_tokens = len(
        re.findall(
            r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]+",
            url
        )
    )

    # Entropy
    url_entropy = shannon_entropy(url)
    hostname_entropy = shannon_entropy(hostname)

    # HTTPS
    is_https = int(
        parsed.scheme.lower() == "https"
    )

    return {
        "URLLength": url_length,
        "DomainLength": hostname_length,
        "IsDomainIP": is_ip,
        "TLDLength": len(tld),
        "NoOfSubDomain": subdomain_count,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": encoded_chars,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": equals_count,
        "NoOfQMarkInURL": question_count,
        "NoOfAmpersandInURL": ampersand_count,
        "NoOfOtherSpecialCharsInURL": special_chars,
        "SpacialCharRatioInURL": special_ratio,
        "IsHTTPS": is_https,
        "TLD": tld,
        "PathLength": path_length,
        "QueryLength": query_length,
        "FragmentLength": fragment_length,
        "NoOfDots": dot_count,
        "NoOfHyphens": hyphen_count,
        "NoOfUnderscores": underscore_count,
        "NoOfSlashes": slash_count,
        "NoOfAtSymbols": at_count,
        "NoOfPercentSymbols": percent_count,
        "NoOfHashSymbols": hash_count,
        "NoOfDigitsInDomain": hostname_digits,
        "DomainDigitRatio": hostname_digit_ratio,
        "NoOfHyphensInDomain": hostname_hyphens,
        "PathSlashCount": path_slashes,
        "PathHyphenCount": path_hyphens,
        "PathUnderscoreCount": path_underscores,
        "PathDigitRatio": path_digit_ratio,
        "PathEntropy": path_entropy,
        "NoOfQueryParameters": query_parameters,
        "QueryDigitRatio": query_digit_ratio,
        "RepeatedSpecialChars": repeated_special_chars,
        "MixedAlphaNumericTokens": mixed_tokens,
        "SuspiciousTokenCount": suspicious_token_count,
        "URLEntropy": url_entropy,
        "DomainEntropy": hostname_entropy
    }


# ============================================================
# Load Final Model
# ============================================================

@st.cache_resource
def load_model():

    return joblib.load(
        "final_phishing_url_model.pkl"
    )


try:

    final_model = load_model()

except Exception as e:

    st.error(
        "Could not load the model file."
    )

    st.code(str(e))

    st.stop()


# ============================================================
# Header
# ============================================================

st.title("🛡️ Phishing URL Detector")

st.write(
    "Enter a website URL to determine whether it is "
    "likely legitimate or phishing using a Machine Learning model."
)

st.info(
    "The prediction is a machine-learning result and "
    "should not be considered a guarantee of website safety."
)


# ============================================================
# URL Input
# ============================================================

url = st.text_input(
    "🔗 Enter URL",
    placeholder="https://example.com"
)


check_button = st.button(
    "🔍 Check URL",
    type="primary"
)


# ============================================================
# Prediction
# ============================================================

if check_button:

    if not url.strip():

        st.warning(
            "Please enter a URL first."
        )

    else:

        try:

            # Extract URL features
            features = extract_enhanced_url_features(
                url
            )

            input_df = pd.DataFrame(
                [features]
            )

            # Prediction
            prediction = final_model.predict(
                input_df
            )[0]

            probabilities = (
                final_model
                .predict_proba(input_df)[0]
            )

            # Map probabilities safely according
            # to the model class order
            classes = list(
                final_model.classes_
            )

            phishing_probability = (
                probabilities[
                    classes.index(0)
                ]
                if 0 in classes
                else 0.0
            )

            legitimate_probability = (
                probabilities[
                    classes.index(1)
                ]
                if 1 in classes
                else 0.0
            )

            # ====================================================
            # Result
            # ====================================================

            st.subheader(
                "Prediction Result"
            )

            if prediction == 0:

                st.error(
                    "🚨 PHISHING URL"
                )

            else:

                st.success(
                    "✅ LEGITIMATE URL"
                )

            # ====================================================
            # Probabilities
            # ====================================================

            col1, col2 = st.columns(2)

            with col1:

                st.metric(
                    "Phishing Probability",
                    f"{phishing_probability:.2%}"
                )

            with col2:

                st.metric(
                    "Legitimate Probability",
                    f"{legitimate_probability:.2%}"
                )

            # ====================================================
            # Probability Bars
            # ====================================================

            st.write(
                "### Probability Distribution"
            )

            st.progress(
                float(phishing_probability),
                text=(
                    f"Phishing: "
                    f"{phishing_probability:.2%}"
                )
            )

            st.progress(
                float(legitimate_probability),
                text=(
                    f"Legitimate: "
                    f"{legitimate_probability:.2%}"
                )
            )

            # ====================================================
            # Extracted Features
            # ====================================================

            with st.expander(
                "📊 View Extracted URL Features"
            ):

                feature_df = pd.DataFrame(
                    list(features.items()),
                    columns=[
                        "Feature",
                        "Value"
                    ]
                )

                st.dataframe(
                    feature_df,
                    use_container_width=True,
                    hide_index=True
                )

        except Exception as e:

            st.error(
                "An error occurred while processing the URL."
            )

            st.code(
                str(e)
            )


# ============================================================
# Footer
# ============================================================

st.markdown("---")

st.caption(
    "Phishing URL Detection using Machine Learning | "
    "HistGradientBoostingClassifier"
)
