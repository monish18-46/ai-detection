import re
import os
import json
import pandas as pd
import uuid
from datetime import datetime
from langdetect import detect
from deep_translator import GoogleTranslator
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

# 👉 Enable colors (especially for Windows)
try:
    from colorama import init
    init()
except:
    pass

# ---------------- LOG FILE ----------------
LOG_FILE = "scam_logs.csv"

# ---------------- AI MODEL ----------------
data = {
    "text": [
        "Your account is blocked click here",
        "Verify your bank account now",
        "Send OTP to update KYC",
        "Win cash prize click link",
        "Urgent action required login now",
        "Account suspended verify immediately",
        "Meeting at 5pm today",
        "Let's go for lunch",
        "Project deadline tomorrow",
        "Happy birthday bro",
        "See you in class",
        "Call me later"
    ],
    "label": [
        "scam","scam","scam","scam","scam","scam",
        "safe","safe","safe","safe","safe","safe"
    ]
}

df = pd.DataFrame(data)

model = Pipeline([
    ("vectorizer", CountVectorizer()),
    ("classifier", MultinomialNB())
])

model.fit(df["text"], df["label"])

def ai_predict(msg):
    prediction = model.predict([msg])[0]
    probability = model.predict_proba([msg]).max()
    return prediction.upper(), round(probability, 2)

# ---------------- LANGUAGE DETECTION ----------------
def detect_language(msg):
    try:
        code = detect(msg)

        language_map = {
            "en": "English",
            "hi": "Hindi",
            "ta": "Tamil",
            "te": "Telugu",
            "kn": "Kannada",
            "ml": "Malayalam",
            "mr": "Marathi",
            "bn": "Bengali",
            "gu": "Gujarati",
            "pa": "Punjabi",
            "ur": "Urdu"
        }

        return language_map.get(code, f"Unknown ({code})")

    except:
        return "Unknown"

# ---------------- TRANSLATION ----------------
def translate_to_english(msg):
    try:
        return GoogleTranslator(source='auto', target='en').translate(msg)
    except:
        return msg

# ---------------- KEYWORDS ----------------
KEYWORDS = {
    "click": 20, "urgent": 25, "verify": 20, "kyc": 20,
    "account": 10, "blocked": 20, "login": 15,
    "otp": 25, "bank": 15, "update": 10, "suspended": 20
}

# ---------------- HIGHLIGHT ----------------
def highlight_words(msg):
    words = msg.split()
    return " ".join([
        f"[{w.upper()}]" if w.lower().strip(".,!?") in KEYWORDS else w
        for w in words
    ])

# ---------------- ENTITY EXTRACTION ----------------
def extract_entities(msg):
    return {
        "upi_ids": re.findall(r'\b[\w.-]+@[\w]+\b', msg),
        "links": re.findall(r'http[s]?://\S+', msg),
        "amounts": re.findall(r'₹\d+|\d+\s?rs', msg.lower())
    }

# ---------------- RISK ENGINE ----------------
def calculate_risk(msg):
    msg_lower = msg.lower()
    risk = 0
    reasons = []

    for word, score in KEYWORDS.items():
        if word in msg_lower:
            risk += score
            reasons.append(f"Keyword detected: {word}")

    if "http" in msg_lower:
        risk += 30
        reasons.append("Contains link")

    return risk, reasons

# ---------------- LOGGING ----------------
def log_result(result):
    row = {
        "timestamp": result["meta"]["timestamp"],
        "text": result["input"]["original_text"],
        "language": result["input"]["language"],
        "risk_level": result["analysis"]["risk"]["level"],
        "risk_score": result["analysis"]["risk"]["score"],
        "ai_label": result["analysis"]["ai_prediction"]["label"],
        "confidence": result["analysis"]["ai_prediction"]["confidence"]
    }

    df_row = pd.DataFrame([row])

    if not os.path.exists(LOG_FILE):
        df_row.to_csv(LOG_FILE, index=False)
    else:
        df_row.to_csv(LOG_FILE, mode='a', header=False, index=False)

# ---------------- PRETTY PRINT (COLOR + BOLD) ----------------
def pretty_print(result):
    BOLD = "\033[1m"
    END = "\033[0m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"

    print("\n" + "="*60)
    print(f"{BOLD}{CYAN}🚨 SCAM DETECTION RESULT{END}")
    print("="*60)

    # INPUT
    print(f"\n{BLUE}📩 Message:{END} {BOLD}{result['input']['original_text']}{END}")
    print(f"{BLUE}🌍 Language:{END} {BOLD}{result['input']['language']}{END}")
    print(f"{BLUE}🔤 Translated:{END} {BOLD}{result['input']['translated_text']}{END}")

    # AI Prediction
    print(f"\n{CYAN}🤖 AI PREDICTION{END}")
    label = result['analysis']['ai_prediction']['label']
    conf = result['analysis']['ai_prediction']['confidence']

    label_color = GREEN if label == "SAFE" else RED
    print(f"   Label: {BOLD}{label_color}{label}{END}")
    print(f"   Confidence: {BOLD}{conf}{END}")

    # Risk
    print(f"\n{CYAN}⚠️ RISK ANALYSIS{END}")
    level = result['analysis']['risk']['level']
    score = result['analysis']['risk']['score']

    if level == "HIGH":
        risk_color = RED
    elif level == "MEDIUM":
        risk_color = YELLOW
    else:
        risk_color = GREEN

    print(f"   Level: {BOLD}{risk_color}{level}{END}")
    print(f"   Score: {BOLD}{score}{END}")

    # Entities
    print(f"\n{CYAN}🔎 ENTITIES{END}")
    print(f"   UPI IDs: {BOLD}{result['entities']['upi_ids']}{END}")
    print(f"   Links: {BOLD}{result['entities']['links']}{END}")
    print(f"   Amounts: {BOLD}{result['entities']['amounts']}{END}")

    # Insights
    print(f"\n{CYAN}🧠 INSIGHTS{END}")
    print(f"   Highlighted: {BOLD}{result['insights']['highlighted_text']}{END}")

    print("\n   Reasons:")
    for r in result['insights']['reasons']:
        print(f"   - {BOLD}{r}{END}")

    # Advice
    advice = result['insights']['advice']
    advice_color = RED if level == "HIGH" else (YELLOW if level == "MEDIUM" else GREEN)

    print(f"\n💡 Advice: {BOLD}{advice_color}{advice}{END}")

    print("\n" + "="*60)

# ---------------- MAIN FUNCTION ----------------
def analyze_text(msg):
    request_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()

    language = detect_language(msg)
    translated = translate_to_english(msg)

    risk, reasons = calculate_risk(translated)
    ai_label, ai_conf = ai_predict(translated)
    entities = extract_entities(msg)

    # Risk level
    if risk >= 60 or ai_label == "SCAM":
        level = "HIGH"
    elif risk >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Advice
    if level == "HIGH":
        advice = "Do NOT click links or send money."
    elif level == "MEDIUM":
        advice = "Be cautious. Verify before acting."
    else:
        advice = "Looks safe, but stay alert."

    explanation = ", ".join(reasons) if reasons else "No strong indicators"

    result = {
        "status": "success",
        "meta": {
            "request_id": request_id,
            "timestamp": timestamp
        },
        "input": {
            "original_text": msg,
            "translated_text": translated,
            "language": language
        },
        "analysis": {
            "risk": {
                "level": level,
                "score": risk,
                "confidence": round(min(risk / 100, 1.0), 2)
            },
            "ai_prediction": {
                "label": ai_label,
                "confidence": ai_conf
            }
        },
        "entities": entities,
        "insights": {
            "highlighted_text": highlight_words(msg),
            "reasons": reasons,
            "explanation": explanation,
            "advice": advice
        }
    }

    log_result(result)
    return result

# ---------------- RUN ----------------
if __name__ == "__main__":
    msg = input("Enter message: ")
    result = analyze_text(msg)

    # 🔥 Beautiful CLI Output
    pretty_print(result)