import streamlit as st
import pandas as pd

st.set_page_config(page_title="Scam Detector AI", layout="centered")

st.title("🚨 AI Scam Message Detector")
st.write("Paste any message and check if it's SAFE or SCAM.")

# ✅ Safe import
try:
    from backend import analyze_text
except Exception as e:
    st.error(f"Backend import error: {e}")
    st.stop()

# ---------------- INPUT ----------------
msg = st.text_area("Enter message:", height=150)

# ---------------- BUTTON ----------------
if st.button("Analyze 🚀"):

    if msg.strip() == "":
        st.warning("Please enter a message")
    else:
        try:
            result = analyze_text(msg)
        except Exception as e:
            st.error(f"Error in backend: {e}")
            st.stop()

        # ---------------- RESULT ----------------
        st.subheader("🔍 Result")

        level = result["analysis"]["risk"]["level"]
        score = result["analysis"]["risk"]["score"]
        label = result["analysis"]["ai_prediction"]["label"]

        if level == "HIGH":
            st.error(f"🚨 HIGH RISK ({score})")
        elif level == "MEDIUM":
            st.warning(f"⚠️ MEDIUM RISK ({score})")
        else:
            st.success(f"✅ LOW RISK ({score})")

        st.write(f"**AI Prediction:** {label}")

        # ---------------- DETAILS ----------------
        st.subheader("📊 Details")
        st.json(result["analysis"])

        st.subheader("🧠 Insights")
        st.write("**Advice:**", result["insights"]["advice"])
        st.write("**Reason:**", result["insights"]["explanation"])

        st.write("**Highlighted Text:**")
        st.markdown(result["insights"]["highlighted_text"])

        # ---------------- ENTITIES ----------------
        st.subheader("🔎 Detected Entities")
        st.json(result["entities"])

        # ---------------- LOG VIEW ----------------
        st.subheader("📁 Latest Logs Preview")

        try:
            df = pd.read_csv("scam_logs.csv")
            st.dataframe(df.tail(10))
        except:
            st.info("No logs found yet.")