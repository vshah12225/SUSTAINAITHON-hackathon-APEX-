"""In-Vehicle CAN Log Analyzer.
Parses raw CAN telemetry files (CSV, TXT, SocketCAN) and performs
sliding-window intrusion detection and antibody synthesis.
"""
import re
from collections import Counter, defaultdict

# Matches various CAN frame logging formats:
# 1. HCRL TXT: "Timestamp: 1478198376.123456        ID: 0000    000    DLC: 8    00 00 00 00 00 00 00 00"
# 2. SocketCAN: "(1478198376.123456) can0 000#0000000000000000" or "can0 000 [8] 00 00 00 00 00 00 00 00"
# 3. CSV: "1478198376.123456,0000,8,00,00,00,00,00,00,00,00,T"
RE_HCRL = re.compile(r"Timestamp:\s*([\d.]+)\s+ID:\s*([0-9a-fA-F]+)")
RE_SOCKETCAN_1 = re.compile(r"\(([\d.]+)\)\s+\w+\s+([0-9a-fA-F]{3,8})#([0-9a-fA-F]*)")
RE_SOCKETCAN_2 = re.compile(r"\w+\s+([0-9a-fA-F]{3,8})\s+\[(\d+)\]\s+(.*)")

SAFETY_CRITICAL = {"0x0B0": "Emergency Braking", "0x2C0": "Steering Assist"}
LEGIT_IDS = {"0x244": "Wheel Speed", "0x3F0": "Instrument Cluster", "0x0B0": "Braking", "0x2C0": "Steering"}


def parse_can_file_content(text_content, max_frames=50_000):
    """Parses text content into structured CAN frame list: (timestamp, hex_id_str, int_id, dlc)."""
    frames = []
    lines = text_content.strip().splitlines()
    
    simulated_ts = 0.0
    for line in lines:
        if not line or line.startswith("#") or line.startswith("//"):
            continue
            
        line_clean = line.strip()
        ts, hex_id, dlc = None, None, 8
        
        # Format 1: HCRL Timestamp / ID
        m_hcrl = RE_HCRL.search(line_clean)
        if m_hcrl:
            try:
                ts = float(m_hcrl.group(1))
                int_id = int(m_hcrl.group(2), 16)
                hex_id = f"0x{int_id:03X}"
            except ValueError:
                pass
                
        # Format 2: SocketCAN candump (ts) can0 ID#DATA
        if not hex_id:
            m_sc1 = RE_SOCKETCAN_1.search(line_clean)
            if m_sc1:
                try:
                    ts = float(m_sc1.group(1))
                    int_id = int(m_sc1.group(2), 16)
                    hex_id = f"0x{int_id:03X}"
                except ValueError:
                    pass

        # Format 3: CSV separated (ts, id, ...)
        if not hex_id and "," in line_clean:
            parts = line_clean.split(",")
            try:
                ts = float(parts[0])
                int_id = int(parts[1].replace("0x", ""), 16)
                hex_id = f"0x{int_id:03X}"
                if len(parts) > 2 and parts[2].isdigit():
                    dlc = int(parts[2])
            except (ValueError, IndexError):
                pass
                
        if hex_id:
            if ts is None:
                ts = simulated_ts
                simulated_ts += 0.0005
            frames.append({
                "ts": ts,
                "hex_id": hex_id,
                "int_id": int_id,
                "dlc": dlc
            })
            if len(frames) >= max_frames:
                break
                
    return frames


def analyze_can_frames(frames, window_sec=0.25):
    """Analyzes a stream of CAN frames for frequency anomalies and flood patterns."""
    if not frames:
        return {
            "total_frames": 0,
            "duration": 0.0,
            "unique_ids": 0,
            "anomaly_detected": False,
            "threat": "NO_DATA",
            "antibody": None,
            "stats": []
        }
        
    start_ts = frames[0]["ts"]
    end_ts = frames[-1]["ts"]
    duration = max(0.001, end_ts - start_ts)
    
    # Calculate ID distributions
    id_counts = Counter(f["hex_id"] for f in frames)
    total_frames = len(frames)
    unique_ids = len(id_counts)
    
    # Calculate windowed spikes (frames per window_sec)
    windows = defaultdict(lambda: Counter())
    for f in frames:
        w_idx = int((f["ts"] - start_ts) / window_sec)
        windows[w_idx][f["hex_id"]] += 1
        
    # Anomaly detection: check if any ID has an abnormal frequency spike
    # Typical automotive CAN traffic runs at 10-100 Hz (2.5 - 25 frames per 0.25s window).
    # A flood attack spikes to >300-1000 frames per window.
    flagged_id = None
    max_rate = 0
    threat_type = "CLEAN_TRAFFIC"
    
    for hex_id, count in id_counts.items():
        avg_rate_hz = count / duration
        # Check windowed burst peak
        peak_in_window = max(w[hex_id] for w in windows.values()) if windows else 0
        peak_rate_hz = peak_in_window / window_sec
        
        # Intrusion criteria: ID rate > 400 Hz or peak burst > 600 Hz
        # or dominates >40% of all vehicle traffic on bus
        is_flood = (peak_rate_hz > 500) or (avg_rate_hz > 300) or (count > 0.40 * total_frames and unique_ids > 5)
        
        if is_flood and peak_rate_hz > max_rate:
            max_rate = peak_rate_hz
            flagged_id = hex_id
            threat_type = "CAN_FLOOD"
            
    # Synthesize antibody if anomaly found
    antibody = None
    if flagged_id:
        action = "BLOCK"
        if flagged_id in SAFETY_CRITICAL:
            action = "RATE_LIMIT"  # Never hard block safety critical functions
        antibody = {
            "target_id": flagged_id,
            "action": action,
            "threat": threat_type,
            "max_allowed_hz": 50,
            "reason": f"Frequency spike detected: {max_rate:.0f} Hz (normal: <50 Hz)"
        }
        
    # Build Top 6 IDs Table
    stats = []
    for hex_id, count in id_counts.most_common(6):
        avg_hz = count / duration
        is_bad = (hex_id == flagged_id)
        desc = SAFETY_CRITICAL.get(hex_id) or LEGIT_IDS.get(hex_id) or "Standard Telemetry"
        stats.append({
            "CAN Arbitration ID": hex_id,
            "Packets": count,
            "Avg Rate": f"{avg_hz:.1f} Hz",
            "Bus Load": f"{(count / total_frames):.1%}",
            "Function": desc,
            "Status": "🚨 INTRUSION / FLOOD" if is_bad else "✅ Normal"
        })
        
    return {
        "total_frames": total_frames,
        "duration": duration,
        "unique_ids": unique_ids,
        "anomaly_detected": bool(flagged_id),
        "threat": threat_type,
        "flagged_id": flagged_id,
        "antibody": antibody,
        "stats": stats
    }
