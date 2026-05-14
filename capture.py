# capture.py — Generate live_traffic.csv from UNSW-NB15 dataset
# This is used ONLY for training the AI model
# The Live Monitor page still captures REAL live packets

import pandas as pd
import numpy as np
import os

DATASET_PATH = "dataset/UNSW_NB15_training-set.csv"
OUTPUT_FILE  = "live_traffic.csv"
NUM_ROWS     = 50000

print("=" * 60)
print("   LIVE IDS — GENERATING TRAINING DATA")
print("   Source: UNSW-NB15 Dataset")
print("=" * 60)

if not os.path.exists(DATASET_PATH):
    print(f"ERROR: Dataset not found at '{DATASET_PATH}'")
    exit(1)

print(f"Loading dataset...")
df = pd.read_csv(DATASET_PATH)
print(f"Loaded {len(df)} rows")
print(f"Columns: {list(df.columns)}")

live_df = pd.DataFrame()

# Protocol
if "proto" in df.columns:
    proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
    live_df["protocol"] = df["proto"].apply(
        lambda x: proto_map.get(str(x).lower().strip(), 0))
else:
    live_df["protocol"] = 6

# Source port
for col in ["sport", "src_port", "Sport"]:
    if col in df.columns:
        live_df["src_port"] = pd.to_numeric(
            df[col], errors="coerce").fillna(0).astype(int)
        break
else:
    live_df["src_port"] = 0

# Destination port
for col in ["dport", "dst_port", "Dport"]:
    if col in df.columns:
        live_df["dst_port"] = pd.to_numeric(
            df[col], errors="coerce").fillna(0).astype(int)
        break
else:
    live_df["dst_port"] = 0

# Packet length
for col in ["spkts", "Spkts", "pkt_len", "sbytes"]:
    if col in df.columns:
        live_df["pkt_len"] = pd.to_numeric(
            df[col], errors="coerce").fillna(60).astype(int)
        break
else:
    live_df["pkt_len"] = 60

# TTL
for col in ["sttl", "ttl", "Sttl"]:
    if col in df.columns:
        live_df["ttl"] = pd.to_numeric(
            df[col], errors="coerce").fillna(64).astype(int)
        break
else:
    live_df["ttl"] = 64

# IHL
for col in ["ihl", "swin"]:
    if col in df.columns:
        live_df["ihl"] = pd.to_numeric(
            df[col], errors="coerce").fillna(5).astype(int)
        break
else:
    live_df["ihl"] = 5

# TOS
if "tos" in df.columns:
    live_df["tos"] = pd.to_numeric(
        df["tos"], errors="coerce").fillna(0).astype(int)
else:
    live_df["tos"] = 0

# Fragment offset
for col in ["frag_offset", "smeansz"]:
    if col in df.columns:
        live_df["frag_offset"] = pd.to_numeric(
            df[col], errors="coerce").fillna(0).astype(int)
        break
else:
    live_df["frag_offset"] = 0

# TCP flags
for col in ["tcp_flags", "tcprtt", "Sttl"]:
    if col in df.columns:
        live_df["tcp_flags"] = (
            pd.to_numeric(df[col], errors="coerce")
            .fillna(0).multiply(100).astype(int))
        break
else:
    live_df["tcp_flags"] = 0

# LABEL — this is the most important part
# UNSW-NB15 uses: 0 = normal, 1 = attack
if "label" in df.columns:
    live_df["label"] = df["label"].apply(
        lambda x: "attack" if str(x).strip() in
        ["1", "1.0", "attack", "Attack"] else "normal")
elif "Label" in df.columns:
    live_df["label"] = df["Label"].apply(
        lambda x: "attack" if str(x).strip() in
        ["1", "1.0", "attack", "Attack"] else "normal")
elif "attack_cat" in df.columns:
    live_df["label"] = df["attack_cat"].apply(
        lambda x: "normal" if str(x).strip() in
        ["", "Normal", "normal", "nan", "None"]
        else "attack")
else:
    live_df["label"] = "normal"

# Sample rows
if len(live_df) > NUM_ROWS:
    print(f"Sampling {NUM_ROWS} rows...")
    live_df = live_df.sample(
        n=NUM_ROWS, random_state=42).reset_index(drop=True)

live_df = live_df.fillna(0)
live_df.to_csv(OUTPUT_FILE, index=False)

print(f"\nSaved {len(live_df)} rows to '{OUTPUT_FILE}'")
print(f"\nLabel distribution:")
print(live_df["label"].value_counts().to_string())
print(f"\nSample:")
print(live_df.head(3).to_string())
print("\nNext step: python train_model.py")
print("=" * 60)