import streamlit as st
import pandas as pd
import re
from backend import analyze_text

# ---------------- CONFIG ----------------
st.set_page_config(
    page_title="Scam Detection AI Pro",
    page_icon="🚨",
    layout="wide"
)

# ---------------- CSS ----------------
st.markdown("""
<style>

.card {
    padding: 16px;
    border-radius: 14px;
    background: #0b1220;
    border: 1px solid #2a3441;
    margin-bottom: 12px;
    color: white;
}

.title {
    font-size: 13px;
    color: #aab4c0;
    font-weight: 600;
}

.value {
    font-size: 28px;
    font-weight: 900;
    color: #ffffff;
}

.sub {
    font-size: 13px;
    color: #cbd5e1;
}

.high {color:#ff4d4d;}
.medium {color:#ffb020;}
.low {color:#00e676;}

.badge {
    padding: 4px 10px;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 700;
    display: inline-block;
    margin-top: 6px;
}

.upi-box {
    background:#111827;
    padding:10px;
    border-radius:10px;
    border:1px solid #374151;
    font-family: monospace;
    font-weight: bold;
    color:#00e5ff;
    margin-bottom:6px;
}

.amount-box {
    background:#111827;
    padding:10px;
    border-radius:10px;
    border:1px solid #374151;
    font-weight: 900;
    color:#00ff88;
    margin-bottom:6px;
}

a {
    color: #4da6ff !important;
    font-weight: 600;
}

</style>
""", unsafe_allow_html=True)

# ---------------- FIXED AMOUNT EXTRACTION ----------------
def clean_amounts(amounts):
    cleaned = []

    for a in amounts:
        a = str(a)

        # FULL SAFE MATCH (NO SPLITTING, NO TRUNCATION)
        matches = re.findall(
            r"(₹\s?\d{1,3}(?:,\d{2,3})*(?:\.\d+)?|\$\s?\d{1,3}(?:,\d{2,3})*(?:\.\d+)?|\b\d{4,}\b)",
            a
        )

        for m in matches:
            cleaned.append(m.replace(" ", ""))

    return cleaned


def extract_links(text):
    return re.findall(r"(https?://[^\s]+)", str(text))


def smart_advice(level, score):
    if level == "HIGH" or score > 75:
        return "🚨 HIGH RISK: Do NOT trust this message."
    elif level == "MEDIUM" or score > 40:
        return "⚠️ MEDIUM RISK: Verify before acting."
    else:
        return "✅ LOW RISK: Appears safe."


# ---------------- SIDEBAR ----------------
st.sidebar.title("⚙️ Controls")
mode = st.sidebar.radio("Select Mode", ["Single Scan", "Bulk Scan", "Analytics"])

# ---------------- HEADER ----------------
st.title("🚨 Scam Detection AI Pro Dashboard")

# =========================
# SINGLE SCAN
# =========================
if mode == "Single Scan":

    st.subheader("🔍 Message Analysis Engine")

    user_input = st.text_area("Enter message", height=140)

    if st.button("Analyze") and user_input.strip():

        result = analyze_text(user_input)

        risk = result['analysis']['risk']
        ai = result['analysis']['ai_prediction']
        entities = result['entities']

        amounts = clean_amounts(entities.get("amounts", []))
        links = extract_links(user_input)
        upi = entities.get("upi_ids", [])

        st.divider()

        # ---------------- KPI CARDS ----------------
        c1, c2, c3 = st.columns(3)

        risk_color = "high" if risk['level']=="HIGH" else "medium" if risk['level']=="MEDIUM" else "low"

        c1.markdown(f"""
        <div class="card">
            <div class="title">🤖 AI PREDICTION</div>
            <div class="value">{ai['label']}</div>
            <div class="sub">Confidence: <b>{round(ai['confidence']*100,1)}%</b></div>
        </div>
        """, unsafe_allow_html=True)

        c2.markdown(f"""
        <div class="card">
            <div class="title">⚠️ RISK SCORE</div>
            <div class="value {risk_color}">{risk['score']}/100</div>
            <div class="badge {risk_color}">{risk['level']} RISK</div>
        </div>
        """, unsafe_allow_html=True)

        c3.markdown(f"""
        <div class="card">
            <div class="title">🌍 LANGUAGE</div>
            <div class="value">{result['input']['language'].upper()}</div>
        </div>
        """, unsafe_allow_html=True)

        # ---------------- RISK ----------------
        st.subheader("📊 Risk Meter")
        st.progress(min(risk['score']/100, 1.0))

        # ---------------- REASONS ----------------
        st.subheader("🧠 Why this result?")
        for r in result['insights']['reasons']:
            st.write("•", r)

        # ---------------- HIGHLIGHT ----------------
        st.subheader("📝 Highlighted Message")
        st.code(result['insights']['highlighted_text'])

        # ---------------- ENTITIES ----------------
        st.subheader("🔎 Extracted Data")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.write("💳 UPI IDs")
            if upi:
                for u in upi:
                    st.markdown(f"<div class='upi-box'>🔹 {u}</div>", unsafe_allow_html=True)
            else:
                st.info("None detected")

        with col2:
            st.write("🔗 Links")
            if links:
                for l in links:
                    st.markdown(f"<div class='upi-box'>🔗 <a href='{l}' target='_blank'>{l}</a></div>", unsafe_allow_html=True)
            else:
                st.info("None detected")

        with col3:
            st.write("💰 Amounts")
            if amounts:
                for a in amounts:
                    st.markdown(f"<div class='amount-box'>💰 <b>{a}</b></div>", unsafe_allow_html=True)
            else:
                st.info("None detected")

        # ---------------- FINAL ----------------
        st.subheader("💡 Final Decision")
        st.info(smart_advice(risk['level'], risk['score']))

        # ---------------- QUICK INSIGHT ----------------
        st.subheader("📈 Quick Insight")

        st.bar_chart(pd.DataFrame({
            "Metric": ["Risk Score", "AI Confidence"],
            "Value": [risk['score'], int(ai['confidence']*100)]
        }).set_index("Metric"))

# =========================
# BULK SCAN
# =========================
elif mode == "Bulk Scan":

    st.subheader("📂 Bulk Scan System")

    file = st.file_uploader("Upload CSV (must contain 'text' column)")

    if file:
        df = pd.read_csv(file)

        if "text" not in df.columns:
            st.error("CSV must contain 'text' column")
        else:
            results = []

            for msg in df["text"]:
                res = analyze_text(str(msg))

                results.append({
                    "text": msg,
                    "prediction": res['analysis']['ai_prediction']['label'],
                    "risk": res['analysis']['risk']['level'],
                    "score": res['analysis']['risk']['score']
                })

            out = pd.DataFrame(results)

            st.success("Scan Completed")
            st.dataframe(out)

            st.download_button(
                "Download Results",
                out.to_csv(index=False),
                "scam_report.csv"
            )

# =========================
# ANALYTICS
# =========================
elif mode == "Analytics":

    st.subheader("📊 Scam Intelligence Dashboard")

    try:
        df = pd.read_csv("scam_logs.csv")

        if df.empty:
            st.warning("No data available")
        else:

            total = len(df)
            high = len(df[df["risk_level"]=="HIGH"])
            medium = len(df[df["risk_level"]=="MEDIUM"])
            low = len(df[df["risk_level"]=="LOW"])

            c1, c2, c3, c4 = st.columns(4)

            c1.metric("Total", total)
            c2.metric("High", high)
            c3.metric("Medium", medium)
            c4.metric("Low", low)

            st.divider()

            st.subheader("📊 Risk Distribution")
            st.bar_chart(df["risk_level"].value_counts())

            st.subheader("🚨 High Risk Messages")

            if "text" in df.columns:
                st.dataframe(
                    df[df["risk_level"]=="HIGH"][["text","risk_score"]]
                    .sort_values("risk_score", ascending=False)
                    .head(10)
                )

            st.subheader("🧠 System Insight")

            avg = df["risk_score"].mean()

            if avg > 70:
                st.error("🚨 High scam activity detected")
            elif avg > 40:
                st.warning("⚠️ Moderate scam activity")
            else:
                st.success("✅ System stable")

    except FileNotFoundError:
        st.warning("No logs found yet. Run scans first.")