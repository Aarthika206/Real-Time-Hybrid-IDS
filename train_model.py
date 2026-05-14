# ============================================================
# train_model.py — Train AI model on captured traffic
# Run with: python train_model.py
# ============================================================

import pandas as pd
import numpy as np
import joblib
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble         import RandomForestClassifier, ExtraTreesClassifier
from sklearn.model_selection  import train_test_split
from sklearn.preprocessing    import LabelEncoder
from sklearn.metrics          import (accuracy_score, precision_score,
                                      recall_score, f1_score,
                                      classification_report, confusion_matrix)

DATA_FILE = "live_traffic.csv"

FEATURE_COLS = [
    "protocol", "src_port", "dst_port",
    "pkt_len", "ttl", "ihl", "tos",
    "frag_offset", "tcp_flags"
]

print("=" * 60)
print("   LIVE IDS — MODEL TRAINING")
print("=" * 60)

# ── Load data ─────────────────────────────────────────────────
if not os.path.exists(DATA_FILE):
    print(f"ERROR: {DATA_FILE} not found.")
    print("Run  python capture.py  first.")
    exit(1)

df = pd.read_csv(DATA_FILE)
print(f"Loaded {len(df)} records from {DATA_FILE}")
print(f"Label distribution:\n{df['label'].value_counts()}\n")

# ── Encode labels ──────────────────────────────────────────────
le_label = LabelEncoder()
df['label_enc'] = le_label.fit_transform(df['label'])
joblib.dump(le_label, 'label_encoder.pkl')

# ── Feature / target split ─────────────────────────────────────
X = df[FEATURE_COLS].fillna(0)
y = df['label_enc']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y if y.nunique() > 1 else None
)

print(f"Training samples : {len(X_train)}")
print(f"Testing  samples : {len(X_test)}\n")

# ── Train both models ──────────────────────────────────────────
print("Training Random Forest ...")
rfc = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rfc.fit(X_train, y_train)
rfc_score = accuracy_score(y_test, rfc.predict(X_test)) * 100

print("Training Extra Trees ...")
etc = ExtraTreesClassifier(n_estimators=100, random_state=42, n_jobs=-1)
etc.fit(X_train, y_train)
etc_score = accuracy_score(y_test, etc.predict(X_test)) * 100

print(f"\nRandom Forest accuracy : {rfc_score:.2f}%")
print(f"Extra Trees  accuracy  : {etc_score:.2f}%")

# ── Pick best model ────────────────────────────────────────────
best_model = rfc if rfc_score >= etc_score else etc
best_name  = "Random Forest" if rfc_score >= etc_score else "Extra Trees"
print(f"\nBest model: {best_name}")

# ── Evaluate ───────────────────────────────────────────────────
y_pred = best_model.predict(X_test)

acc  = round(accuracy_score (y_test, y_pred) * 100, 2)
prec = round(precision_score(y_test, y_pred, average='weighted', zero_division=0) * 100, 2)
rec  = round(recall_score   (y_test, y_pred, average='weighted', zero_division=0) * 100, 2)
f1   = round(f1_score       (y_test, y_pred, average='weighted', zero_division=0) * 100, 2)
report = classification_report(y_test, y_pred,
                                target_names=le_label.classes_,
                                output_dict=True, zero_division=0)

print(f"\nAccuracy  : {acc}%")
print(f"Precision : {prec}%")
print(f"Recall    : {rec}%")
print(f"F1 Score  : {f1}%")

# ── Confusion matrix ───────────────────────────────────────────
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=le_label.classes_,
            yticklabels=le_label.classes_)
plt.title("Confusion Matrix")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.tight_layout()
plt.savefig("confusion_matrix.png", dpi=150)
plt.close()
print("Saved confusion_matrix.png")

# ── Save everything ────────────────────────────────────────────
joblib.dump(best_model, 'ids_model.pkl')
joblib.dump(FEATURE_COLS, 'feature_cols.pkl')
joblib.dump({
    'accuracy'  : acc,
    'precision' : prec,
    'recall'    : rec,
    'f1'        : f1,
    'rfc_score' : round(rfc_score, 2),
    'etc_score' : round(etc_score, 2),
    'classes'   : list(le_label.classes_),
    'report'    : report,
    'best_model': best_name,
}, 'model_metrics.pkl')

print("\nSaved: ids_model.pkl, feature_cols.pkl, model_metrics.pkl")
print("\nNext step: streamlit run app.py")
print("=" * 60)