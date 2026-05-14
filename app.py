# ============================================================
# app.py — Hybrid IDS Streamlit Dashboard
# Run with: streamlit run app.py
# ============================================================

import streamlit as st
st.set_page_config(
    page_title="Hybrid IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import joblib
import os
import smtplib
import threading
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

try:
    from web_threat_detector import full_url_check, check_file_virustotal
    WEB_OK = True
except Exception:
    WEB_OK = False

try:
    from hids_monitor import start_hids, get_hids_alerts
    HIDS_OK = True
except Exception:
    HIDS_OK = False

# ── Custom CSS ──────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;600&display=swap');
.stApp { background:linear-gradient(135deg,#050d1a 0%,#0a1628 50%,#060e1e 100%);
         color:#e0f7fa; font-family:'Rajdhani',sans-serif; }
[data-testid="stSidebar"] { background:linear-gradient(180deg,#030810 0%,#060f1e 100%) !important;
                             border-right:1px solid rgba(0,229,255,0.15); }
header[data-testid="stHeader"] { display:none; }
[data-testid="metric-container"] { background:#0a1628; border:1px solid rgba(0,229,255,0.15);
                                    border-radius:12px; padding:16px; }
[data-testid="stMetricLabel"] p { color:#4a7fa5 !important;
                                   font-family:'Share Tech Mono',monospace !important;
                                   font-size:11px !important; letter-spacing:2px !important;
                                   text-transform:uppercase; }
[data-testid="stMetricValue"] { color:#00e5ff !important;
                                  font-family:'Orbitron',sans-serif !important;
                                  font-size:26px !important; }
.ids-card  { background:#0a1628; border:1px solid rgba(0,229,255,0.15);
             border-radius:16px; padding:24px; margin-bottom:20px; }
.ids-title { font-family:'Orbitron',sans-serif; font-size:26px; font-weight:900;
             color:#00e5ff; letter-spacing:3px; margin-bottom:4px; }
.ids-subtitle { font-family:'Share Tech Mono',monospace; font-size:12px; color:#4a7fa5;
                letter-spacing:3px; text-transform:uppercase; margin-bottom:28px; }
.section-header { font-family:'Orbitron',sans-serif; font-size:13px; color:#00e5ff;
                  letter-spacing:3px; text-transform:uppercase;
                  border-bottom:1px solid rgba(0,229,255,0.15);
                  padding-bottom:8px; margin-bottom:16px; }
.badge-safe   { background:rgba(105,255,71,0.15); border:1px solid #69ff47; color:#69ff47;
                padding:8px 24px; border-radius:20px; font-family:'Orbitron',sans-serif;
                font-size:16px; display:inline-block; }
.badge-attack { background:rgba(255,64,129,0.15); border:1px solid #ff4081; color:#ff4081;
                padding:8px 24px; border-radius:20px; font-family:'Orbitron',sans-serif;
                font-size:16px; display:inline-block; }
.stButton>button { background:linear-gradient(135deg,#00e5ff22,#00e5ff44) !important;
                   border:1px solid #00e5ff !important; color:#00e5ff !important;
                   font-family:'Orbitron',sans-serif !important; font-size:12px !important;
                   letter-spacing:2px !important; border-radius:8px !important;
                   padding:10px 24px !important; }
.alert-row  { background:rgba(255,64,129,0.08); border-left:3px solid #ff4081;
              padding:8px 14px; margin:4px 0; border-radius:4px; font-size:13px; }
.normal-row { background:rgba(105,255,71,0.06); border-left:3px solid #69ff47;
              padding:8px 14px; margin:4px 0; border-radius:4px; font-size:13px; }
.warn-row   { background:rgba(255,215,64,0.08); border-left:3px solid #ffd740;
              padding:8px 14px; margin:4px 0; border-radius:4px; font-size:13px; }
hr { border-color:rgba(0,229,255,0.15) !important; }
[data-testid="stNumberInput"] label,
[data-testid="stNumberInput"] label p {
    color:#00e5ff !important;
    font-family:'Share Tech Mono',monospace !important;
    font-size:11px !important; letter-spacing:1.5px !important;
    text-transform:uppercase !important;
}
</style>
""", unsafe_allow_html=True)

# ── Session state ───────────────────────────────────────────
for k, v in {
    'live_log'       : [],
    'capture_running': False,
    'total_packets'  : 0,
    'total_attacks'  : 0,
    'sender_email'   : '',
    'app_password'   : '',
    'receiver_email' : '',
    'email_alerts'   : True,
    'hids_started'   : False,
}.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── Load model ──────────────────────────────────────────────
@st.cache_resource
def load_model():
    out = {}
    for key, fname in [('model','ids_model.pkl'),('metrics','model_metrics.pkl'),
                        ('features','feature_cols.pkl'),('encoder','label_encoder.pkl')]:
        if os.path.exists(fname):
            out[key] = joblib.load(fname)
    return out

arts  = load_model()
ready = 'model' in arts

# ── Email helper ────────────────────────────────────────────
def send_alert(sender, password, receiver, attack_type, src_ip, dst_ip, confidence):
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 HYBRID IDS ALERT: {attack_type.upper()} from {src_ip}"
        msg['From']    = sender
        msg['To']      = receiver
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html = f"""
        <html><body style="font-family:Arial;background:#050d1a;color:#e0f7fa;padding:30px;">
        <div style="max-width:600px;margin:auto;background:#0a1628;
                    border:1px solid #ff4081;border-radius:16px;padding:30px;">
          <h1 style="color:#ff4081;">🚨 INTRUSION DETECTED</h1>
          <hr style="border-color:#00e5ff33;">
          <table style="width:100%;border-collapse:collapse;margin-top:16px;">
            <tr><td style="color:#4a7fa5;padding:8px;">TIME</td>
                <td style="color:#e0f7fa;padding:8px;">{ts}</td></tr>
            <tr style="background:#ffffff08;">
                <td style="color:#4a7fa5;padding:8px;">ALERT TYPE</td>
                <td style="color:#ff4081;font-weight:bold;font-size:18px;padding:8px;">
                    {attack_type.upper()}</td></tr>
            <tr><td style="color:#4a7fa5;padding:8px;">SOURCE</td>
                <td style="color:#ffd740;padding:8px;">{src_ip}</td></tr>
            <tr style="background:#ffffff08;">
                <td style="color:#4a7fa5;padding:8px;">DESTINATION</td>
                <td style="color:#e0f7fa;padding:8px;">{dst_ip}</td></tr>
            <tr><td style="color:#4a7fa5;padding:8px;">CONFIDENCE</td>
                <td style="color:#00e5ff;font-weight:bold;padding:8px;">{confidence}%</td></tr>
          </table>
          <p style="margin-top:24px;color:#4a7fa5;font-size:12px;">
              Automated alert — Hybrid IDS System</p>
        </div></body></html>"""
        msg.attach(MIMEText(html, 'html'))
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()
    except Exception:
        pass

# ── Feature extraction ──────────────────────────────────────
FEATURE_COLS_DEFAULT = [
    "protocol","src_port","dst_port","pkt_len",
    "ttl","ihl","tos","frag_offset","tcp_flags"
]

def extract(packet):
    try:
        if not packet.haslayer(IP):
            return None
        ip    = packet[IP]
        proto = ip.proto
        sport, dport, flags = 0, 0, 0
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = int(packet[TCP].flags)
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        return {
            "src_ip"      : ip.src,   "dst_ip"   : ip.dst,
            "protocol"    : proto,    "src_port" : sport,
            "dst_port"    : dport,    "pkt_len"  : len(packet),
            "ttl"         : ip.ttl,   "ihl"      : ip.ihl,
            "tos"         : ip.tos,   "frag_offset": int(ip.frag),
            "tcp_flags"   : flags,
        }
    except Exception:
        return None

# ══════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div style='text-align:center;padding:20px 0 10px;'>
      <div style='font-size:42px'>🛡️</div>
      <div style='font-family:Orbitron,sans-serif;font-size:13px;color:#00e5ff;
                  letter-spacing:3px;margin-top:8px;'>HYBRID IDS</div>
      <div style='font-family:Share Tech Mono,monospace;font-size:10px;color:#4a7fa5;
                  letter-spacing:2px;margin-top:4px;'>INTRUSION DETECTION SYSTEM</div>
    </div><hr>""", unsafe_allow_html=True)

    page = st.radio("", [
        "🏠  Home",
        "📡  Live Monitor",
        "🔍  Manual Predict",
        "📈  Model Performance",
        "🌐  Web Threat Scanner",
        "🖥️  HIDS Monitor",
        "📧  Alert Settings",
    ])
    st.markdown("<hr>", unsafe_allow_html=True)

    if ready and 'metrics' in arts:
        m = arts['metrics']
        st.metric("Accuracy",  f"{m['accuracy']}%")
        st.metric("F1 Score",  f"{m['f1']}%")
        st.metric("Packets",   f"{st.session_state.total_packets}")
        st.metric("Attacks",   f"{st.session_state.total_attacks}")
    else:
        st.warning("⚠️ Run capture.py then train_model.py first")

# ══════════════════════════════════════════════════════════════
# PAGE 1 — HOME
# ══════════════════════════════════════════════════════════════
if "Home" in page:
    st.markdown("<div class='ids-title'>HYBRID INTRUSION</div>", unsafe_allow_html=True)
    st.markdown("<div class='ids-title' style='color:#ff4081;margin-top:-8px;'>DETECTION SYSTEM</div>",
                unsafe_allow_html=True)
    st.markdown("<div class='ids-subtitle'>NIDS + HIDS + Web Threat Detection</div>",
                unsafe_allow_html=True)

    if ready and 'metrics' in arts:
        m = arts['metrics']
        c1,c2,c3,c4 = st.columns(4)
        c1.metric("🎯 Accuracy",  f"{m['accuracy']}%")
        c2.metric("🔬 Precision", f"{m['precision']}%")
        c3.metric("📡 Recall",    f"{m['recall']}%")
        c4.metric("⚡ F1 Score",  f"{m['f1']}%")

    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div class='ids-card'>
          <div class='section-header'>📡 NIDS</div>
          <p style='font-size:14px;line-height:1.9;color:#a0c4d8;'>
            Monitors <b style='color:#00e5ff'>network packets</b> in real time.
            Uses a <b style='color:#00e5ff'>Random Forest AI</b> to classify
            traffic as Normal or Attack instantly.
          </p>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class='ids-card'>
          <div class='section-header'>🖥️ HIDS</div>
          <p style='font-size:14px;line-height:1.9;color:#a0c4d8;'>
            Monitors your <b style='color:#00e5ff'>computer itself</b> —
            file changes, suspicious processes and
            <b style='color:#ff4081'>failed login attempts.</b>
          </p>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class='ids-card'>
          <div class='section-header'>🌐 WEB THREATS</div>
          <p style='font-size:14px;line-height:1.9;color:#a0c4d8;'>
            Checks URLs and files against
            <b style='color:#00e5ff'>VirusTotal</b> and
            <b style='color:#00e5ff'>Google Safe Browsing</b>
            to detect malware and phishing.
          </p>
        </div>""", unsafe_allow_html=True)

    st.markdown("<div class='section-header'>ATTACK TYPES DETECTED</div>", unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        <div class='ids-card'>
          <p style='margin:8px 0;font-size:14px;'><span style='color:#ff4081'>■</span>
            <b style='color:#e0f7fa'> Port Scan</b>
            <span style='color:#4a7fa5'> — Reconnaissance attack</span></p>
          <p style='margin:8px 0;font-size:14px;'><span style='color:#ffd740'>■</span>
            <b style='color:#e0f7fa'> DoS / DDoS</b>
            <span style='color:#4a7fa5'> — Flood attack</span></p>
          <p style='margin:8px 0;font-size:14px;'><span style='color:#ff4081'>■</span>
            <b style='color:#e0f7fa'> Phishing</b>
            <span style='color:#4a7fa5'> — Fake websites stealing data</span></p>
          <p style='margin:8px 0;font-size:14px;'><span style='color:#ffd740'>■</span>
            <b style='color:#e0f7fa'> Malware Download</b>
            <span style='color:#4a7fa5'> — Malicious files</span></p>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class='ids-card'>
          <p style='margin:8px 0;font-size:14px;'><span style='color:#e040fb'>■</span>
            <b style='color:#e0f7fa'> File Tampering</b>
            <span style='color:#4a7fa5'> — Unauthorized file changes</span></p>
          <p style='margin:8px 0;font-size:14px;'><span style='color:#ff4081'>■</span>
            <b style='color:#e0f7fa'> Brute Force Login</b>
            <span style='color:#4a7fa5'> — Repeated failed logins</span></p>
          <p style='margin:8px 0;font-size:14px;'><span style='color:#e040fb'>■</span>
            <b style='color:#e0f7fa'> Suspicious Process</b>
            <span style='color:#4a7fa5'> — Hacking tools detected</span></p>
          <p style='margin:8px 0;font-size:14px;'><span style='color:#69ff47'>■</span>
            <b style='color:#e0f7fa'> Normal Traffic</b>
            <span style='color:#4a7fa5'> — Safe and clean</span></p>
        </div>""", unsafe_allow_html=True)

    st.markdown("<div class='section-header'>SYSTEM PIPELINE</div>", unsafe_allow_html=True)
    steps = ["📡 Capture\nPackets","🤖 AI\nClassify","🌐 Web\nScan","🖥️ HIDS\nMonitor","🚨 Alert\n& Report"]
    cols  = st.columns(len(steps))
    for col, step in zip(cols, steps):
        col.markdown(f"""
        <div style='text-align:center;background:#0a1628;
                    border:1px solid rgba(0,229,255,0.15);border-radius:10px;
                    padding:12px 4px;font-size:11px;color:#a0c4d8;
                    font-family:Share Tech Mono,monospace;
                    white-space:pre-line;line-height:1.5;'>{step}</div>""",
                    unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════
# PAGE 2 — LIVE MONITOR
# ══════════════════════════════════════════════════════════════
elif "Live" in page:
    st.markdown("<div class='ids-title' style='font-size:22px;'>📡 LIVE NETWORK MONITOR</div>",
                unsafe_allow_html=True)
    st.markdown("<div class='ids-subtitle'>Real-time packet capture and AI classification</div>",
                unsafe_allow_html=True)

    if not ready:
        st.error("⚠️ Model not loaded. Run capture.py then train_model.py first.")
        st.stop()
    if not SCAPY_OK:
        st.error("⚠️ Scapy not available. Run: pip install scapy")
        st.stop()

    model     = arts['model']
    feat_cols = arts.get('features', FEATURE_COLS_DEFAULT)
    le        = arts.get('encoder', None)

    ctrl1, ctrl2, ctrl3 = st.columns(3)
    with ctrl1:
        n_packets = st.number_input("Packets per capture", 10, 500, 50, step=10)
    with ctrl2:
        st.session_state.email_alerts = st.checkbox(
            "Email alerts on attack", value=st.session_state.email_alerts)
    with ctrl3:
        st.markdown("<br>", unsafe_allow_html=True)
        run_btn = st.button("▶ CAPTURE & ANALYSE", use_container_width=True)

    st.markdown("---")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Packets",  st.session_state.total_packets)
    m2.metric("Total Attacks",  st.session_state.total_attacks)
    m3.metric("Normal Traffic", st.session_state.total_packets - st.session_state.total_attacks)
    attack_rate = (round(st.session_state.total_attacks /
                         st.session_state.total_packets * 100, 1)
                   if st.session_state.total_packets else 0)
    m4.metric("Attack Rate", f"{attack_rate}%")

    if run_btn:
        captured = []
        def collect(pkt):
            f = extract(pkt)
            if f:
                captured.append(f)
        with st.spinner(f"Capturing {n_packets} live packets..."):
            try:
                sniff(prn=collect, count=n_packets, store=False, timeout=30)
            except Exception as e:
                st.error(f"Capture failed: {e}\n\nRun as Administrator!")
                st.stop()
        if not captured:
            st.warning("No packets captured. Run as Administrator.")
        else:
            df_cap = pd.DataFrame(captured)
            X = (df_cap[feat_cols].fillna(0)
                 if all(c in df_cap for c in feat_cols)
                 else pd.DataFrame(0, index=df_cap.index, columns=feat_cols))
            preds  = model.predict(X)
            probas = model.predict_proba(X)
            new_attacks = 0
            for row, pred, proba in zip(captured, preds, probas):
                conf       = round(float(max(proba)) * 100, 1)
                label_name = le.inverse_transform([pred])[0] if le else str(pred)
                is_attack  = label_name.lower() != 'normal'
                if is_attack:
                    new_attacks += 1
                st.session_state.live_log.insert(0, {
                    'time'      : datetime.now().strftime('%H:%M:%S'),
                    'src_ip'    : row['src_ip'],   'dst_ip'    : row['dst_ip'],
                    'protocol'  : row['protocol'], 'pkt_len'   : row['pkt_len'],
                    'label'     : label_name,      'confidence': conf,
                    'is_attack' : is_attack,
                })
                if is_attack and st.session_state.email_alerts:
                    s = st.session_state.sender_email
                    p = st.session_state.app_password
                    r = st.session_state.receiver_email
                    if s and p and r:
                        threading.Thread(target=send_alert,
                            args=(s,p,r,label_name,row['src_ip'],row['dst_ip'],conf),
                            daemon=True).start()
            st.session_state.total_packets += len(captured)
            st.session_state.total_attacks += new_attacks
            st.session_state.live_log = st.session_state.live_log[:200]
            st.success(f"✅ Analysed {len(captured)} packets — {new_attacks} attacks found.")
            st.rerun()

    st.markdown("<div class='section-header'>LIVE PACKET LOG</div>", unsafe_allow_html=True)
    if not st.session_state.live_log:
        st.info("No packets analysed yet. Click ▶ CAPTURE & ANALYSE to start.")
    else:
        for entry in st.session_state.live_log[:50]:
            css   = "alert-row" if entry['is_attack'] else "normal-row"
            icon  = "🚨" if entry['is_attack'] else "✅"
            color = "#ff4081" if entry['is_attack'] else "#69ff47"
            st.markdown(f"""
            <div class='{css}'>
              {icon} <b style='color:{color}'>{entry['label'].upper()}</b>
              &nbsp;|&nbsp;
              <span style='color:#4a7fa5;font-family:monospace;font-size:12px;'>
                  {entry['time']}</span>
              &nbsp;&nbsp;{entry['src_ip']} → {entry['dst_ip']}
              &nbsp;&nbsp;proto={entry['protocol']}
              &nbsp;&nbsp;len={entry['pkt_len']}
              &nbsp;&nbsp;<span style='color:#00e5ff'>{entry['confidence']}%</span>
            </div>""", unsafe_allow_html=True)

        if len(st.session_state.live_log) >= 2:
            st.markdown("<br><div class='section-header'>TRAFFIC DISTRIBUTION</div>",
                        unsafe_allow_html=True)
            log_df = pd.DataFrame(st.session_state.live_log)
            vc = log_df['label'].value_counts().reset_index()
            vc.columns = ['Label', 'Count']
            fig = px.pie(vc, values='Count', names='Label', hole=0.5,
                         color_discrete_sequence=px.colors.qualitative.Bold)
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)',
                              plot_bgcolor='rgba(0,0,0,0)',
                              font_color='#e0f7fa',
                              margin=dict(t=10,b=10), height=300)
            st.plotly_chart(fig, use_container_width=True)

# ══════════════════════════════════════════════════════════════
# PAGE 3 — MANUAL PREDICT
# ══════════════════════════════════════════════════════════════
elif "Manual" in page:
    st.markdown("<div class='ids-title' style='font-size:22px;'>🔍 MANUAL PACKET PREDICT</div>",
                unsafe_allow_html=True)
    st.markdown("<div class='ids-subtitle'>Enter packet values manually to classify</div>",
                unsafe_allow_html=True)

    if not ready:
        st.error("⚠️ Model not loaded.")
        st.stop()

    model     = arts['model']
    feat_cols = arts.get('features', FEATURE_COLS_DEFAULT)
    le        = arts.get('encoder', None)

    st.markdown("<div class='section-header'>PACKET FEATURES</div>", unsafe_allow_html=True)

    FIELD_LABELS = {
        "protocol"    : "🔌 Protocol (TCP=6, UDP=17, ICMP=1)",
        "src_port"    : "📤 Source Port (0–65535)",
        "dst_port"    : "📥 Destination Port (0–65535)",
        "pkt_len"     : "📦 Packet Length (bytes)",
        "ttl"         : "⏱ TTL – Time To Live (default=64)",
        "ihl"         : "📋 IHL – IP Header Length (default=5)",
        "tos"         : "🏷 TOS – Type of Service (usually=0)",
        "frag_offset" : "✂️ Fragment Offset (usually=0)",
        "tcp_flags"   : "🚩 TCP Flags (SYN=2, ACK=16, FIN=1)",
    }
    defaults = {
        "protocol":0,"src_port":0,"dst_port":0,"pkt_len":60,
        "ttl":64,"ihl":5,"tos":0,"frag_offset":0,"tcp_flags":0
    }

    input_vals = {}
    chunks = [feat_cols[i:i+3] for i in range(0, len(feat_cols), 3)]
    for chunk in chunks:
        cols_ui = st.columns(3)
        for ci, feat in enumerate(chunk):
            input_vals[feat] = cols_ui[ci].number_input(
                FIELD_LABELS.get(feat, feat),
                value=float(defaults.get(feat, 0)),
                format="%.4f", key=f"mp_{feat}")

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🚀 CLASSIFY PACKET", use_container_width=True):
        arr   = np.array([[input_vals[f] for f in feat_cols]])
        pred  = arts['model'].predict(arr)[0]
        proba = arts['model'].predict_proba(arr)[0]
        conf  = round(float(max(proba)) * 100, 2)
        label = le.inverse_transform([pred])[0] if le else str(pred)
        is_normal = label.lower() == 'normal'

        st.markdown("<div class='section-header'>RESULT</div>", unsafe_allow_html=True)
        r1, r2 = st.columns(2)
        with r1:
            icon  = "✅" if is_normal else "🚨"
            badge = "badge-safe" if is_normal else "badge-attack"
            st.markdown(f"""
            <div class='ids-card' style='text-align:center;'>
              <div style='font-size:50px;margin-bottom:12px;'>{icon}</div>
              <div class='{badge}'>{label.upper()}</div>
            </div>""", unsafe_allow_html=True)
        with r2:
            st.markdown(f"""
            <div class='ids-card' style='text-align:center;'>
              <div style='font-family:Orbitron,sans-serif;font-size:38px;
                          color:#00e5ff;'>{conf}%</div>
              <div style='font-family:Share Tech Mono,monospace;font-size:11px;
                          color:#4a7fa5;margin-top:6px;'>MODEL CONFIDENCE</div>
            </div>""", unsafe_allow_html=True)

        if not is_normal:
            st.markdown("<div class='section-header' style='margin-top:16px;'>📧 SEND ALERT</div>",
                        unsafe_allow_html=True)
            with st.expander("Send email alert", expanded=True):
                e1, e2 = st.columns(2)
                with e1:
                    st.text_input("Your Gmail",   key="sender_email")
                    st.text_input("App Password", type="password", key="app_password")
                with e2:
                    st.text_input("Recipient Email", key="receiver_email")
                    st.markdown("<br>", unsafe_allow_html=True)
                    if st.button("📨 SEND", use_container_width=True):
                        s = st.session_state.sender_email
                        p = st.session_state.app_password
                        r = st.session_state.receiver_email
                        if s and p and r:
                            send_alert(s, p, r, label, "Manual", "Manual", conf)
                            st.success(f"✅ Alert sent to {r}!")
                        else:
                            st.error("Fill all email fields.")

# ══════════════════════════════════════════════════════════════
# PAGE 4 — MODEL PERFORMANCE
# ══════════════════════════════════════════════════════════════
elif "Performance" in page:
    st.markdown("<div class='ids-title' style='font-size:22px;'>📈 MODEL PERFORMANCE</div>",
                unsafe_allow_html=True)
    st.markdown("<div class='ids-subtitle'>How accurate is the AI model?</div>",
                unsafe_allow_html=True)

    if 'metrics' not in arts:
        st.error("⚠️ Run train_model.py first.")
        st.stop()

    m = arts['metrics']

    st.markdown("""
    <div class='ids-card'>
      <div class='section-header'>WHAT DO THESE NUMBERS MEAN?</div>
      <p style='font-size:14px;line-height:2;color:#a0c4d8;'>
        <b style='color:#00e5ff'>Accuracy</b>
            — Out of 100 packets, how many did the AI classify correctly?<br>
        <b style='color:#00e5ff'>Precision</b>
            — When AI says ATTACK, how often is it actually an attack?<br>
        <b style='color:#00e5ff'>Recall</b>
            — Out of all real attacks, how many did the AI catch?<br>
        <b style='color:#00e5ff'>F1 Score</b>
            — Combined average of Precision and Recall. The main score.
      </p>
    </div>""", unsafe_allow_html=True)

    c1,c2,c3,c4 = st.columns(4)
    c1.metric("🎯 Accuracy",  f"{m['accuracy']}%")
    c2.metric("🔬 Precision", f"{m['precision']}%")
    c3.metric("📡 Recall",    f"{m['recall']}%")
    c4.metric("⚡ F1 Score",  f"{m['f1']}%")

    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("<div class='section-header'>Model Comparison</div>", unsafe_allow_html=True)
        mdf = pd.DataFrame({'Model':['Extra Trees','Random Forest'],
                            'Accuracy (%)':[m['etc_score'], m['rfc_score']]})
        fig_m = px.bar(mdf, x='Model', y='Accuracy (%)', color='Model',
                       color_discrete_sequence=['#00e5ff','#69ff47'], text='Accuracy (%)')
        fig_m.update_traces(texttemplate='%{text:.2f}%', textposition='outside')
        fig_m.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            font_color='#e0f7fa', showlegend=False,
            xaxis=dict(showgrid=False),
            yaxis=dict(gridcolor='rgba(0,229,255,0.1)',
                       range=[max(0,min(m['etc_score'],m['rfc_score'])-5),105]),
            margin=dict(t=40,b=10))
        st.plotly_chart(fig_m, use_container_width=True)

    with col2:
        st.markdown("<div class='section-header'>Performance Radar</div>", unsafe_allow_html=True)
        cats = ['Accuracy','Precision','Recall','F1 Score','Accuracy']
        vals = [m['accuracy'],m['precision'],m['recall'],m['f1'],m['accuracy']]
        fig_r = go.Figure(go.Scatterpolar(
            r=vals, theta=cats, fill='toself',
            fillcolor='rgba(0,229,255,0.1)',
            line=dict(color='#00e5ff', width=2)))
        fig_r.update_layout(
            polar=dict(bgcolor='rgba(0,0,0,0)',
                       radialaxis=dict(visible=True,
                                       range=[max(0,min(vals)-5),101],
                                       tickfont=dict(color='#4a7fa5',size=9),
                                       gridcolor='rgba(0,229,255,0.15)'),
                       angularaxis=dict(tickfont=dict(color='#e0f7fa',size=12),
                                        gridcolor='rgba(0,229,255,0.1)')),
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#e0f7fa', margin=dict(t=20,b=20))
        st.plotly_chart(fig_r, use_container_width=True)

    st.markdown("<div class='section-header'>Confusion Matrix</div>", unsafe_allow_html=True)
    if os.path.exists('confusion_matrix.png'):
        st.image('confusion_matrix.png', use_column_width=True)
    else:
        st.info("confusion_matrix.png not found. Re-run train_model.py")

    report = m.get('report', {})
    rows   = []
    for key, val in report.items():
        if isinstance(val, dict) and key not in ['accuracy','macro avg','weighted avg']:
            rows.append({'Class':key,
                         'Precision' : f"{val['precision']*100:.2f}%",
                         'Recall'    : f"{val['recall']*100:.2f}%",
                         'F1-Score'  : f"{val['f1-score']*100:.2f}%",
                         'Support'   : int(val['support'])})
    if rows:
        st.markdown("<div class='section-header' style='margin-top:20px;'>Per-Class Report</div>",
                    unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════
# PAGE 5 — WEB THREAT SCANNER
# ══════════════════════════════════════════════════════════════
elif "Web" in page:
    st.markdown("<div class='ids-title' style='font-size:22px;'>🌐 WEB THREAT SCANNER</div>",
                unsafe_allow_html=True)
    st.markdown("<div class='ids-subtitle'>Detect malicious websites, phishing and malware</div>",
                unsafe_allow_html=True)

    if not WEB_OK:
        st.error("⚠️ web_threat_detector.py not found or config.py missing API keys.")
        st.stop()

    tab1, tab2 = st.tabs(["🔗 URL / Website Check", "📁 File Malware Check"])

    with tab1:
        st.markdown("<div class='section-header'>CHECK A URL OR WEBSITE</div>",
                    unsafe_allow_html=True)
        st.markdown("""
        <div class='ids-card'>
          <p style='font-size:13px;color:#a0c4d8;'>
            Enter any website URL. It will be checked against
            <b style='color:#00e5ff'>VirusTotal</b> (70+ antivirus engines) and
            <b style='color:#00e5ff'>Google Safe Browsing</b>
            (phishing and malware database).
          </p>
        </div>""", unsafe_allow_html=True)

        url_input = st.text_input("Enter URL to scan", placeholder="https://example.com")
        if st.button("🔍 SCAN URL", use_container_width=True):
            if url_input:
                with st.spinner("Scanning URL against threat databases..."):
                    result = full_url_check(url_input)
                st.markdown("<div class='section-header'>SCAN RESULT</div>",
                            unsafe_allow_html=True)
                if result["is_threat"]:
                    st.markdown(
                        "<div class='badge-attack'>⚠️ THREAT DETECTED</div><br><br>",
                        unsafe_allow_html=True)
                else:
                    st.markdown(
                        "<div class='badge-safe'>✅ CLEAN — No threats found</div><br><br>",
                        unsafe_allow_html=True)

                col1, col2 = st.columns(2)
                with col1:
                    vt = result.get("virustotal", {})
                    st.markdown("<div class='ids-card'><div class='section-header'>VIRUSTOTAL</div>",
                                unsafe_allow_html=True)
                    st.write(f"🔴 Malicious engines : **{vt.get('malicious','N/A')}**")
                    st.write(f"🟡 Suspicious engines: **{vt.get('suspicious','N/A')}**")
                    st.write(f"✅ Total engines     : **{vt.get('total','N/A')}**")
                    if "error" in vt:
                        st.warning(f"Error: {vt['error']}")
                    st.markdown("</div>", unsafe_allow_html=True)
                with col2:
                    gsb = result.get("safe_browsing", {})
                    st.markdown("<div class='ids-card'><div class='section-header'>GOOGLE SAFE BROWSING</div>",
                                unsafe_allow_html=True)
                    threat_found = gsb.get('is_threat', False)
                    st.write(f"Phishing / Malware: **{'YES ⚠️' if threat_found else 'NO ✅'}**")
                    st.write(f"Threat type       : **{gsb.get('threat_type','None')}**")
                    if "error" in gsb:
                        st.warning(f"Error: {gsb['error']}")
                    st.markdown("</div>", unsafe_allow_html=True)

                if result["is_threat"] and st.session_state.email_alerts:
                    s = st.session_state.sender_email
                    p = st.session_state.app_password
                    r = st.session_state.receiver_email
                    if s and p and r:
                        threading.Thread(target=send_alert,
                            args=(s,p,r,"MALICIOUS URL",url_input,"Web Scanner",100.0),
                            daemon=True).start()
            else:
                st.warning("Please enter a URL.")

    with tab2:
        st.markdown("<div class='section-header'>CHECK A FILE FOR MALWARE</div>",
                    unsafe_allow_html=True)
        st.markdown("""
        <div class='ids-card'>
          <p style='font-size:13px;color:#a0c4d8;'>
            Enter the full path of any file on your computer.
            Its <b style='color:#00e5ff'>SHA-256 hash</b> will be checked
            against VirusTotal's database of known malware — no file is uploaded.
          </p>
        </div>""", unsafe_allow_html=True)

        file_path = st.text_input("Enter full file path",
                                   placeholder=r"C:\Users\you\Downloads\file.exe")
        if st.button("🔍 SCAN FILE", use_container_width=True):
            if file_path:
                if os.path.exists(file_path):
                    with st.spinner("Computing hash and checking VirusTotal..."):
                        result = check_file_virustotal(file_path)
                    if result.get("is_threat"):
                        st.markdown(
                            "<div class='badge-attack'>🚨 MALWARE DETECTED</div><br>",
                            unsafe_allow_html=True)
                        st.error(f"⚠️ {result.get('malicious')} engines flagged this file!")
                        st.write(f"SHA-256: `{result.get('hash','?')}`")
                    elif "error" in result:
                        st.warning(f"Scan error: {result['error']}")
                    else:
                        st.markdown(
                            "<div class='badge-safe'>✅ File appears clean</div><br>",
                            unsafe_allow_html=True)
                        st.write(f"SHA-256: `{result.get('hash','?')}`")
                        if result.get('note'):
                            st.info(f"Note: {result['note']}")
                else:
                    st.error("File not found. Please check the path.")
            else:
                st.warning("Please enter a file path.")

# ══════════════════════════════════════════════════════════════
# PAGE 6 — HIDS MONITOR
# ══════════════════════════════════════════════════════════════
elif "HIDS" in page:
    st.markdown("<div class='ids-title' style='font-size:22px;'>🖥️ HOST IDS MONITOR</div>",
                unsafe_allow_html=True)
    st.markdown("<div class='ids-subtitle'>File integrity, process and login monitoring</div>",
                unsafe_allow_html=True)

    if not HIDS_OK:
        st.error("⚠️ hids_monitor.py not found. Please create the file.")
        st.stop()

    st.markdown("""
    <div class='ids-card'>
      <div class='section-header'>WHAT IS HIDS?</div>
      <p style='font-size:13px;color:#a0c4d8;line-height:1.9;'>
        <b style='color:#00e5ff'>Host IDS</b> watches your computer from the inside.
        It monitors <b style='color:#00e5ff'>file changes</b>
        (did a suspicious .exe appear?),
        <b style='color:#00e5ff'>running processes</b>
        (is any hacking tool running?) and
        <b style='color:#ff4081'>failed login attempts</b>
        (is someone brute-forcing your password?).
      </p>
    </div>""", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("▶ START HIDS", use_container_width=True):
            if not st.session_state.hids_started:
                start_hids()
                st.session_state.hids_started = True
                st.success("✅ HIDS started!")
            else:
                st.info("HIDS is already running.")
    with col2:
        if st.button("🔄 REFRESH ALERTS", use_container_width=True):
            st.rerun()
    with col3:
        status = "🟢 RUNNING" if st.session_state.hids_started else "🔴 STOPPED"
        st.markdown(f"""
        <div class='ids-card' style='text-align:center;padding:12px;'>
          <div style='font-family:Orbitron,sans-serif;font-size:12px;color:#00e5ff;'>
              HIDS STATUS</div>
          <div style='font-size:16px;margin-top:4px;'>{status}</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")
    alerts = get_hids_alerts()
    high   = [a for a in alerts if a["severity"] == "HIGH"]
    medium = [a for a in alerts if a["severity"] == "MEDIUM"]
    low    = [a for a in alerts if a["severity"] == "LOW"]

    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Total Alerts", len(alerts))
    c2.metric("🔴 High",      len(high))
    c3.metric("🟡 Medium",    len(medium))
    c4.metric("🟢 Low",       len(low))

    st.markdown("<div class='section-header'>HIDS ALERT LOG</div>", unsafe_allow_html=True)
    filter_cat = st.selectbox("Filter by category",
                               ["All","File Integrity","Process Monitor","Login Monitor"])
    filtered = alerts if filter_cat == "All" else [
        a for a in alerts if a["category"] == filter_cat]

    if not filtered:
        st.info("No alerts yet. Click ▶ START HIDS — alerts appear as activity is detected.")
    else:
        for alert in filtered[:100]:
            color = {"HIGH":"#ff4081","MEDIUM":"#ffd740","LOW":"#69ff47"}.get(
                alert["severity"],"#e0f7fa")
            css = ("alert-row"  if alert["severity"] == "HIGH" else
                   "warn-row"   if alert["severity"] == "MEDIUM" else "normal-row")
            st.markdown(f"""
            <div class='{css}'>
              <b style='color:{color}'>[{alert["severity"]}]</b>
              <b> {alert["category"]}</b>
              &nbsp;|&nbsp;
              <span style='color:#4a7fa5;font-size:12px;'>{alert["time"]}</span>
              <br>{alert["message"]}
              <br><small style='color:#4a7fa5'>{alert["details"]}</small>
            </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════
# PAGE 7 — ALERT SETTINGS
# ══════════════════════════════════════════════════════════════
elif "Alert" in page:
    st.markdown("<div class='ids-title' style='font-size:22px;'>📧 EMAIL ALERT SETTINGS</div>",
                unsafe_allow_html=True)
    st.markdown("<div class='ids-subtitle'>Configure automatic attack notifications</div>",
                unsafe_allow_html=True)

    st.markdown("""
    <div class='ids-card'>
      <div class='section-header'>HOW TO GET GMAIL APP PASSWORD</div>
      <p style='font-size:14px;color:#a0c4d8;line-height:1.9;'>
        1. Go to <b style='color:#00e5ff'>myaccount.google.com</b><br>
        2. Security → Enable <b>2-Step Verification</b><br>
        3. Search <b>App Passwords</b> in the search bar<br>
        4. Select Mail → Generate → Copy the 16-character password
      </p>
    </div>""", unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.text_input("Your Gmail Address",    key="sender_email",
                      placeholder="you@gmail.com")
        st.text_input("Gmail App Password",    key="app_password",
                      type="password", placeholder="16-char app password")
    with col2:
        st.text_input("Alert Recipient Email", key="receiver_email",
                      placeholder="receiver@gmail.com")
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("📨 SEND TEST EMAIL", use_container_width=True):
            s = st.session_state.sender_email
            p = st.session_state.app_password
            r = st.session_state.receiver_email
            if s and p and r:
                send_alert(s, p, r, "TEST ALERT", "0.0.0.0", "0.0.0.0", 99.0)
                st.success(f"✅ Test alert sent to {r}!")
            else:
                st.error("Please fill all three fields.")

    st.markdown("<br>", unsafe_allow_html=True)
    st.session_state.email_alerts = st.toggle(
        "Enable automatic email alerts for all detections",
        value=st.session_state.email_alerts)
    if st.session_state.email_alerts:
        st.success("✅ Email alerts are ON.")
    else:
        st.warning("⚠️ Email alerts are OFF.")


