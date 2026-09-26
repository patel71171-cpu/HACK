import json
import os
import re
import uuid
from datetime import datetime

import pandas as pd
import streamlit as st
from dotenv import load_dotenv
import snowflake.connector

load_dotenv()

st.set_page_config(
    page_title="PhishGraph",
    page_icon="🛡️",
    layout="wide",
)

DB = os.getenv("SNOWFLAKE_DATABASE", "PHISHGRAPH_DB")
SCHEMA = os.getenv("SNOWFLAKE_SCHEMA", "PUBLIC")
WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE", "")
ROLE = os.getenv("SNOWFLAKE_ROLE", "")
CORTEX_MODEL = os.getenv("CORTEX_MODEL", "snowflake-arctic")

SUSPICIOUS_WORDS = [
    "urgent", "immediately", "verify", "verification", "suspended",
    "suspend", "deleted", "delete", "password", "click here", "confirm",
    "account", "security alert", "winner", "prize", "refund", "invoice",
    "limited time", "act now", "failure", "threat", "locked"
]

DEMO_MESSAGE = (
    "URGENT: Your account will be deleted today. "
    "Click here immediately to verify."
)


def get_connection():
    required = ["SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PASSWORD"]
    missing = [x for x in required if not os.getenv(x)]
    if missing:
        raise RuntimeError(
            "Missing Snowflake settings: " + ", ".join(missing) +
            ". Copy .env.example to .env and fill them in."
        )

    kwargs = {
        "account": os.getenv("SNOWFLAKE_ACCOUNT"),
        "user": os.getenv("SNOWFLAKE_USER"),
        "password": os.getenv("SNOWFLAKE_PASSWORD"),
        "database": DB,
        "schema": SCHEMA,
    }
    if WAREHOUSE:
        kwargs["warehouse"] = WAREHOUSE
    if ROLE:
        kwargs["role"] = ROLE
    return snowflake.connector.connect(**kwargs)


def qident(name):
    # Database/schema/warehouse names come from .env, not user message text.
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", name):
        raise ValueError(f"Unsafe Snowflake identifier: {name}")
    return f'"{name.upper()}"'


def ensure_tables(conn):
    db = qident(DB)
    schema = qident(SCHEMA)

    statements = [
        f"CREATE DATABASE IF NOT EXISTS {db}",
        f"CREATE SCHEMA IF NOT EXISTS {db}.{schema}",
        f"""
        CREATE TABLE IF NOT EXISTS {db}.{schema}.MESSAGES (
            MESSAGE_ID VARCHAR,
            SENDER_DOMAIN VARCHAR,
            SUBJECT VARCHAR,
            MESSAGE_TEXT VARCHAR,
            NUM_LINKS INTEGER,
            SUSPICIOUS_KEYWORDS INTEGER,
            DOMAIN_RISK FLOAT,
            SENDER_KNOWN BOOLEAN,
            CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {db}.{schema}.MESSAGE_FEATURES (
            MESSAGE_ID VARCHAR,
            KEYWORD_SCORE FLOAT,
            UNKNOWN_SENDER_SCORE FLOAT,
            LINK_SCORE FLOAT,
            URGENCY_SCORE FLOAT,
            DOMAIN_SCORE FLOAT,
            CORTEX_RAW VARCHAR,
            CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {db}.{schema}.RISK_RESULTS (
            MESSAGE_ID VARCHAR,
            KEYWORD_POINTS FLOAT,
            UNKNOWN_SENDER_POINTS FLOAT,
            LINK_POINTS FLOAT,
            URGENCY_POINTS FLOAT,
            DOMAIN_POINTS FLOAT,
            RISK_SCORE FLOAT,
            RISK_LEVEL VARCHAR,
            EXPLANATION VARCHAR,
            CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
        )
        """,
    ]

    cur = conn.cursor()
    try:
        for sql in statements:
            cur.execute(sql)
    finally:
        cur.close()


def count_links(text):
    return len(re.findall(r"(?:https?://|www\.)\S+", text, flags=re.I))


def keyword_hits(text):
    low = text.lower()
    hits = [word for word in SUSPICIOUS_WORDS if word in low]
    return sorted(set(hits))


def heuristic_urgency(text):
    low = text.lower()
    urgency_words = [
        "urgent", "immediately", "today", "now", "within 24 hours",
        "last warning", "act now", "expires", "final notice"
    ]
    hits = [w for w in urgency_words if w in low]
    score = min(1.0, len(hits) / 3.0)
    return score, hits


def local_ai_analysis(text):
    """Safe fallback when Cortex is disabled/unavailable."""
    urgency_score, urgency_hits = heuristic_urgency(text)
    low = text.lower()

    manipulation = any(
        phrase in low for phrase in [
            "verify", "confirm", "click here", "reset", "send", "provide",
            "account will", "you must", "required"
        ]
    )
    threatening = any(
        phrase in low for phrase in [
            "deleted", "suspended", "locked", "legal action", "police",
            "penalty", "final warning"
        ]
    )

    if urgency_score >= 0.67:
        explanation = "The message creates time pressure and asks the recipient to act quickly."
    elif manipulation:
        explanation = "The message contains language that pressures the recipient to perform an account or verification action."
    else:
        explanation = "No strong urgency pattern was detected by the local fallback rules."

    return {
        "urgency_score": urgency_score,
        "urgency_hits": urgency_hits,
        "manipulation": manipulation,
        "threatening": threatening,
        "explanation": explanation,
        "source": "local_fallback",
    }


def cortex_analysis(conn, text):
    prompt = f"""
You are analyzing an email for a cybersecurity demonstration.
Do NOT decide whether it is definitely malicious. Identify explainable signals only.

Return JSON only, with exactly these keys:
urgency_score: number from 0 to 1
urgency_hits: array of short phrases
manipulation: boolean
threatening: boolean
explanation: short string, maximum 35 words

Email/message:
{text}
""".strip()

    sql = f"""
        SELECT AI_COMPLETE(
            %s,
            %s,
            OBJECT_CONSTRUCT(
                'temperature', 0,
                'max_tokens', 250
            )
        )
    """

    cur = conn.cursor()
    try:
        cur.execute(sql, (CORTEX_MODEL, prompt))
        raw = cur.fetchone()[0]
    finally:
        cur.close()

    if isinstance(raw, dict):
        data = raw
    else:
        data = json.loads(str(raw))

    if "choices" in data:
        # Some AI_COMPLETE response forms return a choices/messages object.
        msg = data["choices"][0].get("messages", "")
        data = json.loads(msg) if isinstance(msg, str) else msg

    data["urgency_score"] = max(0.0, min(1.0, float(data.get("urgency_score", 0))))
    data["urgency_hits"] = data.get("urgency_hits", [])
    data["manipulation"] = bool(data.get("manipulation", False))
    data["threatening"] = bool(data.get("threatening", False))
    data["explanation"] = str(data.get("explanation", ""))[:500]
    data["source"] = "snowflake_cortex"
    return data


def calculate_features(message, sender_domain, sender_known, domain_risk):
    links = count_links(message)
    hits = keyword_hits(message)

    # Normalized 0..1 feature values.
    keyword_score = min(1.0, len(hits) / 5.0)
    link_score = min(1.0, links / 2.0)
    unknown_sender_score = 0.0 if sender_known else 1.0
    domain_score = max(0.0, min(1.0, float(domain_risk)))

    return {
        "num_links": links,
        "keyword_hits": hits,
        "keyword_score": keyword_score,
        "link_score": link_score,
        "unknown_sender_score": unknown_sender_score,
        "domain_score": domain_score,
    }


def score_features(features, urgency_score):
    keyword_points = features["keyword_score"] * 30
    unknown_points = features["unknown_sender_score"] * 25
    link_points = features["link_score"] * 20
    urgency_points = urgency_score * 15
    domain_points = features["domain_score"] * 10

    score = min(
        100.0,
        keyword_points + unknown_points + link_points +
        urgency_points + domain_points
    )

    if score >= 70:
        level = "HIGH RISK"
    elif score >= 40:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    return {
        "keyword_points": keyword_points,
        "unknown_points": unknown_points,
        "link_points": link_points,
        "urgency_points": urgency_points,
        "domain_points": domain_points,
        "risk_score": score,
        "risk_level": level,
    }


def insert_and_score(conn, message_id, sender_domain, subject, message,
                     features, ai_result, score):
    db = qident(DB)
    schema = qident(SCHEMA)
    cur = conn.cursor()
    try:
        cur.execute(
            f"""
            INSERT INTO {db}.{schema}.MESSAGES
            (MESSAGE_ID, SENDER_DOMAIN, SUBJECT, MESSAGE_TEXT,
             NUM_LINKS, SUSPICIOUS_KEYWORDS, DOMAIN_RISK, SENDER_KNOWN)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                message_id, sender_domain, subject, message,
                features["num_links"], len(features["keyword_hits"]),
                features["domain_score"], features["unknown_sender_score"] == 0
            ),
        )

        cur.execute(
            f"""
            INSERT INTO {db}.{schema}.MESSAGE_FEATURES
            (MESSAGE_ID, KEYWORD_SCORE, UNKNOWN_SENDER_SCORE, LINK_SCORE,
             URGENCY_SCORE, DOMAIN_SCORE, CORTEX_RAW)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                message_id,
                features["keyword_score"],
                features["unknown_sender_score"],
                features["link_score"],
                ai_result["urgency_score"],
                features["domain_score"],
                json.dumps(ai_result),
            ),
        )

        explanation = ai_result["explanation"]
        cur.execute(
            f"""
            INSERT INTO {db}.{schema}.RISK_RESULTS
            (MESSAGE_ID, KEYWORD_POINTS, UNKNOWN_SENDER_POINTS,
             LINK_POINTS, URGENCY_POINTS, DOMAIN_POINTS,
             RISK_SCORE, RISK_LEVEL, EXPLANATION)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                message_id,
                score["keyword_points"],
                score["unknown_points"],
                score["link_points"],
                score["urgency_points"],
                score["domain_points"],
                score["risk_score"],
                score["risk_level"],
                explanation,
            ),
        )
        conn.commit()
    finally:
        cur.close()


def main():
    st.markdown(
        """
        <style>
        .main-title {font-size: 3rem; font-weight: 800; margin-bottom: 0;}
        .subtitle {font-size: 1.1rem; color: #64748b; margin-bottom: 1.5rem;}
        .risk-box {padding: 1.2rem; border-radius: 16px; border: 1px solid #e2e8f0;}
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="main-title">🛡️ PhishGraph</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="subtitle">Explainable Phishing Risk Detector • Snowflake + Cortex + Streamlit</div>',
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.header("Demo Controls")
        use_cortex = st.toggle("Use Snowflake Cortex", value=True)
        st.caption(f"Cortex model: `{CORTEX_MODEL}`")
        st.divider()
        st.markdown("**Scoring weights**")
        st.write("Suspicious keywords — 30%")
        st.write("Unknown sender — 25%")
        st.write("Risky links — 20%")
        st.write("Urgency language — 15%")
        st.write("Domain risk — 10%")
        st.divider()
        st.caption("Synthetic demonstration dataset. Not a production antivirus.")

    col1, col2 = st.columns([1.4, 1])

    with col1:
        st.subheader("Analyze a message")
        demo = st.button("Load demo phishing message")
        if demo:
            st.session_state["message"] = DEMO_MESSAGE

        message = st.text_area(
            "Message text",
            value=st.session_state.get("message", ""),
            height=190,
            placeholder="Paste an email or message here...",
        )

        c1, c2 = st.columns(2)
        with c1:
            sender_domain = st.text_input("Sender domain", "unknown-bank.com")
        with c2:
            subject = st.text_input("Subject", "Urgent account verification")

        c3, c4 = st.columns(2)
        with c3:
            sender_known = st.checkbox("Sender is known", value=False)
        with c4:
            domain_risk = st.slider("Demo domain risk", 0.0, 1.0, 0.8, 0.05)

        analyze = st.button("🔍 Analyze Message", type="primary", use_container_width=True)

    with col2:
        st.subheader("How it works")
        st.info(
            "The final score is calculated from transparent weighted features. "
            "Cortex is used for natural-language urgency/manipulation analysis "
            "and a short explanation."
        )
        st.code(
            "risk =\n"
            "  keywords * 0.30 +\n"
            "  unknown_sender * 0.25 +\n"
            "  risky_links * 0.20 +\n"
            "  urgency * 0.15 +\n"
            "  domain_risk * 0.10",
            language="text",
        )

    if not analyze:
        return

    if not message.strip():
        st.warning("Please paste a message first.")
        return

    message_id = "MSG-" + uuid.uuid4().hex[:10].upper()
    features = calculate_features(
        message, sender_domain, sender_known, domain_risk
    )

    try:
        conn = get_connection()
        ensure_tables(conn)
    except Exception as exc:
        st.error(f"Snowflake connection/setup failed: {exc}")
        st.info("Check your .env values, Snowflake role/warehouse, and network/authentication settings.")
        return

    with st.spinner("Analyzing message..."):
        ai_result = None
        if use_cortex:
            try:
                ai_result = cortex_analysis(conn, message)
            except Exception as exc:
                st.warning(
                    "Cortex analysis failed, so the app used its local fallback rules. "
                    f"Details: {exc}"
                )

        if ai_result is None:
            ai_result = local_ai_analysis(message)

        score = score_features(features, ai_result["urgency_score"])

        insert_and_score(
            conn, message_id, sender_domain, subject, message,
            features, ai_result, score
        )
        conn.close()

    st.divider()
    st.subheader("Risk Assessment")

    r1, r2, r3 = st.columns(3)
    with r1:
        st.metric("Risk Score", f"{score['risk_score']:.0f}/100")
    with r2:
        st.metric("Risk Level", score["risk_level"])
    with r3:
        st.metric("Links Detected", features["num_links"])

    st.progress(int(round(score["risk_score"])) / 100)

    st.subheader("Explainable Score Breakdown")

    breakdown = pd.DataFrame(
        {
            "Signal": [
                "Suspicious keywords",
                "Unknown sender",
                "Risky links",
                "Urgency language",
                "Domain risk",
            ],
            "Points": [
                score["keyword_points"],
                score["unknown_points"],
                score["link_points"],
                score["urgency_points"],
                score["domain_points"],
            ],
            "Weight": ["30%", "25%", "20%", "15%", "10%"],
        }
    )
    st.dataframe(
        breakdown.style.format({"Points": "{:.1f}"}),
        use_container_width=True,
        hide_index=True,
    )

    left, right = st.columns(2)

    with left:
        st.subheader("🚨 Detected Indicators")
        if features["keyword_hits"]:
            st.warning("Suspicious keywords: " + ", ".join(features["keyword_hits"]))
        if features["num_links"] > 0:
            st.warning(f"{features['num_links']} link(s) detected.")
        if not sender_known:
            st.warning("Sender is not marked as known.")
        if ai_result["urgency_hits"]:
            st.warning(
                "Urgency language: " + ", ".join(map(str, ai_result["urgency_hits"]))
            )
        if ai_result["manipulation"]:
            st.warning("Manipulative/request-for-action language detected.")
        if ai_result["threatening"]:
            st.warning("Threatening or consequence-based language detected.")
        if not any([
            features["keyword_hits"], features["num_links"] > 0,
            not sender_known, ai_result["urgency_hits"],
            ai_result["manipulation"], ai_result["threatening"]
        ]):
            st.success("No strong indicator was detected.")

    with right:
        st.subheader("💡 Why this message is risky")
        st.write(ai_result["explanation"])
        st.caption(f"Analysis source: {ai_result['source']}")

        st.subheader("Technical Metadata")
        st.json({
            "message_id": message_id,
            "sender_domain": sender_domain,
            "sender_known": sender_known,
            "domain_risk": features["domain_score"],
            "cortex_model": CORTEX_MODEL if ai_result["source"] == "snowflake_cortex" else None,
        })

    st.caption(
        "Prototype warning: this score is a demonstration of explainable risk scoring, "
        "not proof that a message is malicious or safe."
    )


if __name__ == "__main__":
    main()
