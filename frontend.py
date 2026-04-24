import streamlit as st
import pandas as pd
from backend import analyze_text

# ---------------- CONFIG ----------------
st.set_page_config(
    page_title="Scam Detection AI",
    page_icon="🚨",
    layout="wide"
)

# ---------------- CSS ----------------
st.markdown("""
<style>
.card {
    padding: 18px;
    border-radius: 14px;
    background: #1E1E1E;
    box-shadow: 0 4px 12px rgba(0,0,0,0.6);
    margin-bottom: 15px;
}
.kpi {
    font-size: 22px;
    font-weight: bold;
}
.high {color:#ff4b4b;}
.medium {color:#ffa500;}
.low {color:#00c853;}
</style>
""", unsafe_allow_html=True)

# ---------------- SIDEBAR ----------------
st.sidebar.title("⚙️ Controls")
mode = st.sidebar.radio("Select Mode", ["Single Scan", "Bulk Scan", "Analytics"])

# ---------------- HEADER ----------------
st.title("🚨 Scam Detection AI Platform")

# =========================
# 🔹 SINGLE SCAN MODE
# =========================
if mode == "Single Scan":

    st.subheader("🔍 Smart Message Investigation")

    user_input = st.text_area("📩 Enter Message", height=150)

    if st.button("Analyze Message") and user_input.strip():

        result = analyze_text(user_input)

        st.divider()

        # KPI CARDS
        c1, c2, c3 = st.columns(3)

        with c1:
            st.metric("🤖 Prediction", result['analysis']['ai_prediction']['label'])

        with c2:
            st.metric("⚠️ Risk Score", result['analysis']['risk']['score'])

        with c3:
            st.metric("🌍 Language", result['input']['language'])

        # RISK BAR
        st.subheader("📊 Risk Meter")
        risk_score = result['analysis']['risk']['score']
        st.progress(min(risk_score / 100, 1.0))

        # WHY
        st.subheader("🧠 Why this result?")
        reasons = result['insights']['reasons']

        if reasons:
            for r in reasons:
                st.write(f"• {r}")
        else:
            st.write("No strong indicators")

        # HIGHLIGHT
        st.subheader("📝 Highlighted Message")
        st.code(result['insights']['highlighted_text'])

        # ENTITIES (PRO UI)
        st.subheader("🔎 Extracted Entities")
        entities = result['entities']
        col1, col2, col3 = st.columns(3)

        with col1:
            st.write("💳 UPI IDs")
            if entities['upi_ids']:
                for u in entities['upi_ids']:
                    st.success(u)
            else:
                st.info("None")

        with col2:
            st.write("🌐 Links")
            if entities['links']:
                for l in entities['links']:
                    st.markdown(f"[🔗 Open Link]({l})")
            else:
                st.info("None")

        with col3:
            st.write("💰 Amounts")
            if entities['amounts']:
                for a in entities['amounts']:
                    st.success(a)
            else:
                st.info("None")

        # TRANSLATION
        st.subheader("🔤 Translated Text")
        st.write(result['input']['translated_text'])

        # FINAL DECISION
        st.subheader("💡 Final Advice")
        level = result['analysis']['risk']['level']
        advice = result['insights']['advice']

        if level == "HIGH":
            st.error(advice)
        elif level == "MEDIUM":
            st.warning(advice)
        else:
            st.success(advice)

        # MINI ANALYTICS
        st.subheader("📈 Quick Insight")
        chart_data = {
            "Risk Score": result['analysis']['risk']['score'],
            "AI Confidence": int(result['analysis']['ai_prediction']['confidence'] * 100)
        }
        st.bar_chart(chart_data)

# =========================
# 🔹 BULK SCAN MODE
# =========================
elif mode == "Bulk Scan":

    st.subheader("📂 Upload CSV File")

    uploaded_file = st.file_uploader("Upload CSV with 'text' column")

    if uploaded_file:
        df = pd.read_csv(uploaded_file)

        if "text" not in df.columns:
            st.error("CSV must contain 'text' column")
        else:
            results = []

            for msg in df["text"]:
                res = analyze_text(str(msg))
                results.append({
                    "text": msg,
                    "prediction": res['analysis']['ai_prediction']['label'],
                    "risk": res['analysis']['risk']['level']
                })

            result_df = pd.DataFrame(results)

            st.success("✅ Scan Completed")
            st.dataframe(result_df)

            st.download_button(
                "📥 Download Results",
                result_df.to_csv(index=False),
                "scan_results.csv"
            )

# =========================
# 🔹 ANALYTICS MODE
# =========================
elif mode == "Analytics":

    st.subheader("📊 Analytics Dashboard")

    try:
        df = pd.read_csv("scam_logs.csv")

        if df.empty:
            st.warning("No data yet")
        else:
            total = len(df)
            high = len(df[df["risk_level"] == "HIGH"])
            medium = len(df[df["risk_level"] == "MEDIUM"])
            low = len(df[df["risk_level"] == "LOW"])

            c1, c2, c3, c4 = st.columns(4)

            c1.metric("Total Scans", total)
            c2.metric("High Risk", high)
            c3.metric("Medium Risk", medium)
            c4.metric("Low Risk", low)

            st.subheader("Risk Distribution")
            st.bar_chart(df["risk_level"].value_counts())

    except:
        st.warning("No log file found yet")