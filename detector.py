"""ImmuneFleet core: learns NORMAL CAN traffic only, flags deviations, builds a tiny rule,
checks it with a 3-car consensus and a peer shadow test. The detector never sees attack labels;
labels are used only afterwards for scoring."""
import re, json, math, os
import numpy as np, pandas as pd

WINDOW = 0.1  # seconds per analysis window
BYTES = [f"b{i}" for i in range(8)]

# ---------- data loading (HCRL Car-Hacking dataset format) ----------
_TXT = re.compile(r"Timestamp:\s*([\d.]+)\s+ID:\s*([0-9a-fA-F]+)\s+\S+\s+DLC:\s*(\d)\s*((?:[0-9a-fA-F]{2}\s*)*)")

def _frame(rows):
    return pd.DataFrame(rows, columns=["ts", "id", "dlc"] + BYTES + ["attack"])

def load_hcrl_csv(path, max_rows=400_000):
    """Attack files: ts,id,dlc,b0..b(dlc-1),flag  (flag T = injected, R = normal)."""
    rows = []
    with open(path) as f:
        for i, line in enumerate(f):
            if i >= max_rows: break
            p = line.strip().split(",")
            try:
                dlc = int(p[2]); data = [int(x, 16) for x in p[3:3 + dlc]]
                flag = p[3 + dlc].strip() if len(p) > 3 + dlc else "R"
                data += [0] * (8 - len(data))
                rows.append((float(p[0]), int(p[1], 16), dlc, *data[:8], 1 if flag == "T" else 0))
            except (ValueError, IndexError):
                continue
    return _frame(rows)

def load_hcrl_normal_txt(path, max_rows=400_000):
    rows = []
    with open(path) as f:
        for i, line in enumerate(f):
            if i >= max_rows: break
            m = _TXT.search(line)
            if not m: continue
            data = [int(x, 16) for x in m.group(4).split()]
            data += [0] * (8 - len(data))
            rows.append((float(m.group(1)), int(m.group(2), 16), int(m.group(3)), *data[:8], 0))
    return _frame(rows)

def load_folder(folder):
    """Expects HCRL files: normal_run_data.txt, DoS_dataset.csv, Fuzzy_dataset.csv, gear_dataset.csv, RPM_dataset.csv."""
    normal = load_hcrl_normal_txt(os.path.join(folder, "normal_run_data.txt"))
    names = {"DoS flood": "DoS_dataset.csv", "Fuzzing": "Fuzzy_dataset.csv",
             "Gear spoofing": "gear_dataset.csv", "RPM spoofing": "RPM_dataset.csv"}
    attacks = {k: load_hcrl_csv(os.path.join(folder, v)) for k, v in names.items()
               if os.path.exists(os.path.join(folder, v))}
    return normal, attacks

# ---------- synthetic fallback so the app always runs ----------
def synthetic_world(seed=0, seconds=120):
    rng = np.random.default_rng(seed)
    ids = rng.choice(np.arange(0x100, 0x7FF), 24, replace=False)
    periods = rng.choice([0.01, 0.02, 0.05, 0.1], len(ids))
    base = rng.integers(0, 200, (len(ids), 8))

    def normal_stream(t0, dur, s):
        r = np.random.default_rng(s); rows = []
        for cid, per, b in zip(ids, periods, base):
            t = t0 + r.uniform(0, per)
            while t < t0 + dur:
                data = np.clip(b + r.integers(-3, 4, 8), 0, 255)
                rows.append((t, int(cid), 8, *data, 0)); t += per * r.uniform(0.95, 1.05)
        return rows

    normal = _frame(normal_stream(0, seconds, seed + 1)).sort_values("ts").reset_index(drop=True)

    def with_attack(kind, s, dur=30):
        r = np.random.default_rng(s); rows = normal_stream(0, dur, s)
        a0, a1 = 10, 20
        if kind == "DoS flood":
            for t in np.arange(a0, a1, 0.0003): rows.append((t, 0, 8, *([0] * 8), 1))
        elif kind == "Fuzzing":
            for t in np.arange(a0, a1, 0.0005):
                rows.append((t, int(r.integers(0, 0x7FF)), 8, *r.integers(0, 256, 8), 1))
        elif kind == "Spoofing (signal value)":
            tgt = int(ids[3])
            for t in np.arange(a0, a1, 0.002): rows.append((t, tgt, 8, *([255] * 8), 1))
        elif kind == "Stealth spoofing (low rate)":
            tgt = int(ids[5])
            for t in np.arange(a0, a1, periods[5] * 5.0): rows.append((t, tgt, 8, *np.clip(base[5] + 1, 0, 255), 1))
        return _frame(rows).sort_values("ts").reset_index(drop=True)

    attacks = {k: with_attack(k, 100 + i) for i, k in enumerate(
        ["DoS flood", "Fuzzing", "Spoofing (signal value)", "Stealth spoofing (low rate)"])}
    return normal, attacks

# ---------- features ----------
class Baseline:
    def __init__(self, normal):
        self.known = set(normal["id"].unique())
        w = (normal["ts"] // WINDOW).astype(int)
        cnt = normal.groupby([w, "id"]).size().unstack(fill_value=0)
        self.mu, self.sd = cnt.mean(), cnt.std().fillna(1.0).clip(lower=1.5)
        g = normal.groupby("id")[BYTES]
        self.bmin, self.bmax = g.min(), g.max()

    def windows(self, df):
        w = (df["ts"] // WINDOW).astype(int); out = []
        for k, g in df.groupby(w):
            ids = g["id"].values; vc = pd.Series(ids).value_counts()
            p = vc.values / vc.values.sum()
            unk = np.isin(ids, list(self.known), invert=True).mean()
            z = {i: (c - self.mu.get(i, 0)) / self.sd.get(i, 1.5) for i, c in vc.items()}
            kn = g[g["id"].isin(self.bmin.index)]
            if len(kn):
                lo = self.bmin.loc[kn["id"]].values; hi = self.bmax.loc[kn["id"]].values
                out_rng = ((kn[BYTES].values < lo - 8) | (kn[BYTES].values > hi + 8)).any(axis=1).mean()
            else:
                out_rng = 0.0
            out.append(dict(win=k, n=len(g), uniq=len(vc), entropy=float(-(p * np.log2(p)).sum()),
                            unknown=unk, maxz=max(z.values()), out_of_range=out_rng,
                            label=int(g["attack"].max()), top=sorted(z, key=z.get, reverse=True)[:3],
                            msg_ids=set(ids.tolist())))
        return pd.DataFrame(out)

FEATS = ["n", "uniq", "entropy", "unknown", "maxz", "out_of_range"]

class Detector:
    """Explainable anomaly scorer trained on NORMAL windows only.
    score = largest deviation (in standard deviations) of any traffic feature from normal.
    Window is flagged when score exceeds a threshold set from normal data (no attack labels used)."""
    def __init__(self, normal, margin=1.25):
        self.normal = normal
        cut = normal["ts"].min() + 0.7 * (normal["ts"].max() - normal["ts"].min())
        self.base = Baseline(normal[normal["ts"] <= cut])
        tr = self.base.windows(normal[normal["ts"] <= cut])
        self.test_normal = self.base.windows(normal[normal["ts"] > cut])
        self.mu = tr[FEATS].median()
        self.sd = tr[FEATS].std().clip(lower=1e-3)
        # floors so tiny natural jitter never counts as a big deviation
        self.sd = np.maximum(self.sd, np.array([2, 1, 0.05, 0.02, 1.0, 0.02]))
        self.thr = self.score(tr).quantile(0.995) * margin

    def score(self, wdf):
        z = ((wdf[FEATS] - self.mu) / self.sd).abs()
        return z.max(axis=1)

    def explain(self, wdf):
        z = ((wdf[FEATS] - self.mu) / self.sd).abs()
        return z.idxmax(axis=1)

    def flag(self, wdf):
        return (self.score(wdf) > self.thr).values

    def evaluate(self, attack_df):
        w = self.base.windows(attack_df); f = self.flag(w); lab = w["label"].values == 1
        det = f[lab].mean() if lab.any() else float("nan")
        first = np.argmax(lab & f) if (lab & f).any() else None
        t0 = np.argmax(lab)
        ttd = None if first is None else float((first - t0) * WINDOW)
        fa = self.flag(self.test_normal).mean()
        return dict(detection_rate=float(det), false_alarm_rate=float(fa), time_to_detect_s=ttd)

# ---------- rule, consensus, peer test ----------
UNKNOWN = "UNKNOWN_IDS"

def make_rule(det, wdf, flagged):
    """Tiny rule candidates from one car's flagged windows: specific IDs, or 'any ID never seen in normal traffic'."""
    toks = {}
    fl = wdf[flagged]
    if len(fl) and (fl["unknown"] > 0.3).mean() > 0.5:
        toks[UNKNOWN] = 1
    for top in fl["top"]:
        for i in top[:2]:
            if i in det.base.known: toks[int(i)] = toks.get(int(i), 0) + 1
    return toks

def consensus_round(det, attack_df, n_cars=5, need=3, seed=0):
    """Each simulated car sees a different slice of traffic and runs the detector on its own data."""
    rng = np.random.default_rng(seed); w = det.base.windows(attack_df)
    idx = np.arange(len(w)); rng.shuffle(idx); slices = np.array_split(idx, n_cars)
    votes = []
    for s in slices:
        sub = w.iloc[s]; fl = det.flag(sub)
        votes.append(make_rule(det, sub, fl) if fl.sum() >= 3 else {})
    tally = {}
    for v in votes:
        for t in v: tally[t] = tally.get(t, 0) + 1
    agreed = [t for t, c in tally.items() if c >= need]
    cars_flagging = sum(1 for v in votes if v)
    if not agreed:
        return dict(approved=False, cars_flagging=cars_flagging, rule=None,
                    reason="not enough cars agreed" if cars_flagging else "no car flagged it")
    tn = det.test_normal
    def fires(ids):  # would this rule fire on healthy traffic?
        def f(s):
            return any((t == UNKNOWN and any(i not in det.base.known for i in s)) for t in ids)
        return tn["msg_ids"].apply(f).mean()
    fpr = float(fires(agreed))
    rule = {"match": agreed, "action": "alert + rate-limit", "contains_gps": False,
            "contains_driver_data": False, "shadow_false_positive_rate": fpr}
    rule["size_bytes"] = len(json.dumps(rule))
    ok = fpr <= 0.01
    return dict(approved=ok, cars_flagging=cars_flagging, rule=rule,
                reason="passed peer shadow test" if ok else "failed peer shadow test")

if __name__ == "__main__":
    normal, attacks = synthetic_world()
    det = Detector(normal)
    for name, df in attacks.items():
        r = consensus_round(det, df); print(name, det.evaluate(df), r["approved"], r["reason"], r["cars_flagging"])
