"""Live attack lab: the simulation core (no Streamlit in here, so it can be tested on its own).

Five cars share one running simulation. Each car sees its own CAN traffic (a real recording from data/ if present,
otherwise synthetic ECUs). An attacker, on any device, switches an attack on and off. Every car runs the REAL steps:

    on-car statistical detector -> draft rule -> validator (allowlist) -> sign -> cloud (3-car quorum)
    -> peer test -> signed antibody -> staged rollout -> each car's gateway drops the attack

The cloud is your own cloud.py, the signatures are signing.py, the validator is validator.py. Only the CAN traffic
is simulated, and it is counted per 0.1 s tick instead of frame by frame, so thousands of frames/s cost nothing.
"""
import os
import random
import threading
import time
from bisect import bisect_left
from collections import Counter, deque

from cloud import REQUIRED, Cloud
from pipeline import PERIODS, WIN, parse_frames
from signing import CLOUD_KEY, car_key, sign
from validator import validate

N_CARS = 5
DT = 0.1               # one tick = 0.1 s of bus time
STAGES = [1, 3, N_CARS]  # canary, then about half, then everyone (same as the main demo)
STAGE_DELAY = 1.0      # seconds between rollout stages
PENDING_TTL = 45.0     # a rule that cannot get 3 cars in this long expires
DOS_ID = 0x000         # the ID the real HCRL DoS attack floods
LIMIT_FACTOR = 1.25    # RATE_LIMIT lets a bit more than the normal rate through
HIST = 40              # seconds of sparkline history per car


class Source:
    """Normal CAN traffic. Uses data/normal_run_data.txt (real recording) if it exists, else synthetic periodic ECUs."""

    def __init__(self, data_dir):
        self.real = False
        self.times, self.ids, self.dur = [], [], 0.0
        path = os.path.join(data_dir, "normal_run_data.txt")
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    frames = parse_frames(fh.read(), max_frames=60_000)
                if len(frames) > 1000 and frames[-1][0] - frames[0][0] > 2:
                    t0 = frames[0][0]
                    self.times = [f[0] - t0 for f in frames]
                    self.ids = [f[1] for f in frames]
                    self.dur = self.times[-1]
                    self.real = True
            except OSError:
                pass
        if self.real:
            self.base = {i: c / self.dur for i, c in Counter(self.ids).items()}
        else:
            self.base = {i: 1.0 / p for i, p in PERIODS.items()}

    def new_state(self, seed):
        rng = random.Random(seed)
        return {"rng": rng, "acc": {i: rng.random() for i in PERIODS}}

    def counts(self, st, ci, t):
        """Frames per ID that this car receives during the tick that starts at time t."""
        if self.real:
            a = (t + ci * self.dur / N_CARS) % self.dur
            b = a + DT
            out = Counter(self.ids[bisect_left(self.times, a):bisect_left(self.times, min(b, self.dur))])
            if b > self.dur:
                out.update(self.ids[:bisect_left(self.times, b - self.dur)])
            return out
        out = Counter()
        for i, p in PERIODS.items():
            st["acc"][i] += DT / p * st["rng"].uniform(0.97, 1.03)
            n = int(st["acc"][i])
            st["acc"][i] -= n
            if n:
                out[i] = n
        return out


class StreamDetector:
    """The on-car detector from pipeline.py, made incremental: a sliding 0.5 s window of per-ID counts.
    An ID never seen in normal driving is flagged at 20+ frames per window; a known ID at 3x its normal rate."""

    def __init__(self, baseline):
        self.base = baseline
        self.ticks = deque(maxlen=round(WIN / DT))

    def update(self, counts):
        self.ticks.append(counts)
        if len(self.ticks) < self.ticks.maxlen:
            return {}
        total = Counter()
        for c in self.ticks:
            total.update(c)
        flagged = {}
        for i, n in total.items():
            b = self.base.get(i)
            if (b is None and n >= 20) or (b is not None and n >= 10 and n / WIN > 3 * b):
                flagged[i] = n
        return flagged


def draft_rule(can_id, n, known, t):
    """What the on-car 'AI' proposes. The extra fields are on purpose: the validator must strip them."""
    return {"threat": "SPOOFING" if known else "CAN_FLOOD", "target_id": f"0x{can_id:03X}",
            "action": "RATE_LIMIT" if known else "BLOCK",
            "window_start": round(t - WIN, 1), "window_end": round(t, 1), "frame_count": n}


class LiveCloud(Cloud):
    """Your cloud.py, with every log line also sent to the live event feed."""

    def __init__(self, sink, **kw):
        super().__init__(**kw)
        self._sink = sink

    def log(self, msg):
        super().log(msg)
        self._sink(msg)


class LiveSim:
    def __init__(self, seed=7, data_dir=None):
        self.lock = threading.RLock()
        self.seed = seed
        self.src = Source(data_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
        self.attack = {"on": False, "kind": "dos", "rate": 3000, "cars": [1, 2, 3], "target": 0x316}
        self._thread, self._stop = None, threading.Event()
        self.reset()

    # ---------------------------------------------------------- control
    def reset(self):
        with self.lock:
            self.attack["on"] = False
            self.t = 0.0
            self.events = deque(maxlen=80)
            self.rollout = None
            self.first_attack_t = self.protected_t = None
            self.pending_since = {}
            self.cloud = LiveCloud(self._log_cloud, on_deploy=self._start_rollout, on_release=self._on_release)
            self.cars = [{"id": i + 1, "rng": random.Random(self.seed * 100 + i), "src": self.src.new_state(self.seed * 100 + i),
                          "det": StreamDetector(self.src.base), "rules": {}, "local": set(), "fleet": set(), "carry": {},
                          "attack_since": None, "detect_delay": None, "last_atk_in": 0, "last_atk_drop": 0.0,
                          "sec": [0.0, 0.0, 0], "hist": deque(maxlen=HIST),
                          "tot": {"atk_in": 0.0, "atk_drop": 0.0, "leg_in": 0.0, "leg_drop": 0.0}} for i in range(N_CARS)]

    def set_attack(self, on=None, kind=None, rate=None, cars=None, target=None):
        with self.lock:
            a, was = self.attack, self.attack["on"]
            if kind in ("dos", "inject"):
                a["kind"] = kind
            if rate is not None:
                a["rate"] = max(10, min(8000, int(rate)))
            if cars is not None:
                a["cars"] = sorted({int(c) for c in cars if 1 <= int(c) <= N_CARS})
            if target is not None and int(target) in self.src.base:
                a["target"] = int(target)
            if on is not None:
                a["on"] = bool(on) and bool(a["cars"])
            if a["on"] and not was:
                what = "DoS flood on ID 0x000" if a["kind"] == "dos" else f"injection on ID 0x{a['target']:03X}"
                self.log(f"💥 ATTACKER launched a {what}: {a['rate']:,} frames/s on Car {', '.join(map(str, a['cars']))}")
            elif was and not a["on"]:
                self.log("⏹️ ATTACKER stopped the attack")

    def log(self, msg):
        with self.lock:
            self.events.appendleft((self.t, msg))

    def _log_cloud(self, msg):
        self.log(msg)

    def _on_release(self, car_ids):
        self.log(f"⌛ Rule expired with too few cars. Cars {car_ids} stay locally contained, the fleet was never protected")

    def _start_rollout(self, rule, sig):
        order = sorted(range(N_CARS), key=lambda c: bool(self.cars[c]["local"]) or self.cars[c]["attack_since"] is not None)
        self.rollout = {"rule": rule, "sig": sig, "stage": 0, "next": self.t, "order": order}

    # ---------------------------------------------------------- the tick
    def step(self):
        with self.lock:
            self.t = round(self.t + DT, 6)
            a = self.attack
            for ci, car in enumerate(self.cars):
                legit = self.src.counts(car["src"], ci, self.t)
                attack = Counter()
                if a["on"] and (ci + 1) in a["cars"]:
                    n = int(a["rate"] * DT + car["rng"].random())
                    if n:
                        attack[DOS_ID if a["kind"] == "dos" else a["target"]] = n
                    if car["attack_since"] is None:
                        car["attack_since"] = self.t
                    if self.first_attack_t is None:
                        self.first_attack_t = self.t - DT
                else:
                    car["attack_since"] = None
                flagged = car["det"].update(legit + attack)          # the on-car IDS taps the bus before the gateway
                self._gateway(car, legit, attack)
                if flagged:
                    can_id, n = max(flagged.items(), key=lambda kv: kv[1])
                    if can_id not in car["rules"]:
                        self._detect_and_report(car, can_id, n)
            self._rollout_tick()
            self._expire_tick()

    def _gateway(self, car, legit, attack):
        """Apply this car's rules to the frames of this tick. A gateway cannot tell a real frame from a fake one with the
        same ID, so when it limits an ID, real and fake frames are dropped in proportion."""
        a_in = a_drop = l_in = l_drop = 0.0
        for i in set(legit) | set(attack):
            la, aa = legit.get(i, 0), attack.get(i, 0)
            tot, rule, drop = la + aa, car["rules"].get(i), 0.0
            if rule and rule["action"] == "BLOCK":
                drop = tot
            elif rule and rule["action"] == "RATE_LIMIT":
                limit = LIMIT_FACTOR * self.src.base.get(i, 0.0) * DT
                budget = car["carry"].get(i, 0.0) + limit
                allowed = min(tot, int(budget))
                car["carry"][i] = min(budget - allowed, limit)
                drop = tot - allowed
            frac = drop / tot if tot else 0.0
            a_in += aa; l_in += la; a_drop += aa * frac; l_drop += la * frac
        t = car["tot"]
        t["atk_in"] += a_in; t["atk_drop"] += a_drop; t["leg_in"] += l_in; t["leg_drop"] += l_drop
        car["last_atk_in"], car["last_atk_drop"] = a_in, a_drop
        s = car["sec"]
        s[0] += a_in; s[1] += a_in - a_drop; s[2] += 1
        if s[2] >= round(1 / DT):
            car["hist"].append((s[0], s[1]))
            car["sec"] = [0.0, 0.0, 0]

    def _detect_and_report(self, car, can_id, n):
        cid = car["id"]
        if car["attack_since"] is not None and car["detect_delay"] is None:
            car["detect_delay"] = round(self.t - car["attack_since"] + DT, 2)  # frames of the first tick arrived during the last DT
        known = can_id in self.src.base
        self.log(f"🔴 Car {cid}: anomaly on ID 0x{can_id:03X}, {n} frames in {WIN}s "
                 f"({'known ECU, rate spike' if known else 'ID never seen in normal driving'})")
        draft = draft_rule(can_id, n, known, self.t)
        rule, stripped, reason = validate(draft)
        if stripped:
            self.log(f"🛡️ Validator stripped fields from Car {cid}'s draft: {', '.join(stripped)}")
        if rule is None:
            self.log(f"🛡️ Validator REJECTED Car {cid}'s rule: {reason}")
            return
        car["rules"][can_id] = rule                      # contain the attack on THIS car at once
        car["local"].add(can_id)
        self.log(f"🟠 Car {cid}: contained by its own antibody ({rule['action']} on 0x{can_id:03X})")
        self.cloud.receive(cid, rule, sign(car_key(cid), rule))

    def _rollout_tick(self):
        ro = self.rollout
        if not ro or self.t < ro["next"]:
            return
        tid = int(ro["rule"]["target_id"], 16)
        for ci in ro["order"][:STAGES[ro["stage"]]]:
            if ro["sig"] != sign(CLOUD_KEY, ro["rule"]):
                self.log(f"⛔ Car {ci + 1} REFUSED the antibody: bad cloud signature")
                continue
            self.cars[ci]["rules"][tid] = ro["rule"]
            self.cars[ci]["fleet"].add(tid)
        self.log(f"🚦 Rollout stage {ro['stage'] + 1}/{len(STAGES)}: {STAGES[ro['stage']]} car(s) verified the signature and applied it")
        ro["stage"] += 1
        ro["next"] = self.t + STAGE_DELAY
        if ro["stage"] >= len(STAGES):
            self.rollout, self.protected_t = None, self.t
            self.log("🔵 Whole fleet immune")

    def _expire_tick(self):
        for k in self.cloud.pending:
            self.pending_since.setdefault(k, self.t)
        self.pending_since = {k: s for k, s in self.pending_since.items() if k in self.cloud.pending}
        if any(self.t - s > PENDING_TTL for s in self.pending_since.values()):
            self.cloud.expire_stuck()
            self.pending_since.clear()

    # ---------------------------------------------------------- reading state
    @staticmethod
    def _status(car):
        if car["fleet"]:
            return "blocked" if car["last_atk_in"] > 0 else "immune"
        if car["local"]:
            return "contained"
        return "compromised" if car["attack_since"] is not None else "healthy"

    def snapshot(self):
        """Plain data (safe to hand to any thread or to json) describing everything the UI shows."""
        with self.lock:
            cars, a_in, a_drop, l_in, l_drop = [], 0.0, 0.0, 0.0, 0.0
            for c in self.cars:
                tot = c["tot"]
                a_in += tot["atk_in"]; a_drop += tot["atk_drop"]; l_in += tot["leg_in"]; l_drop += tot["leg_drop"]
                last = c["hist"][-1] if c["hist"] else (0.0, 0.0)
                cars.append({"id": c["id"], "status": self._status(c), "hist": [list(h) for h in c["hist"]],
                             "rate_in": last[0], "rate_pass": last[1], "detect_delay": c["detect_delay"],
                             "rules": sorted(f"{r['action']} 0x{i:03X}" for i, r in c["rules"].items()),
                             "fleet": bool(c["fleet"]), "atk_in": tot["atk_in"], "atk_drop": tot["atk_drop"]})
            delays = [c["detect_delay"] for c in self.cars if c["detect_delay"] is not None]
            ro = self.rollout
            return {"t": self.t, "attack": dict(self.attack, cars=list(self.attack["cars"])), "real_data": self.src.real,
                    "cars": cars, "known_ids": sorted(self.src.base),
                    "pending": [{"key": k, "n": len(e["reports"])} for k, e in self.cloud.pending.items()],
                    "deployed": [{"key": k, "rule": dict(d["rule"]), "sig": d["sig"]} for k, d in self.cloud.deployed.items()],
                    "last_test": dict(self.cloud.last_test) if self.cloud.last_test else None,
                    "rollout": {"stage": ro["stage"], "of": len(STAGES)} if ro else None,
                    "events": [(round(t, 1), m) for t, m in list(self.events)[:14]],
                    "metrics": {"detect_s": min(delays) if delays else None,
                                "protect_s": round(self.protected_t - self.first_attack_t, 1)
                                if self.protected_t is not None and self.first_attack_t is not None else None,
                                "attack_frames": a_in, "blocked_pct": 100 * a_drop / a_in if a_in else None,
                                "legit_frames": l_in, "legit_lost_pct": 100 * l_drop / l_in if l_in else 0.0}}

    # ---------------------------------------------------------- real-time driver
    def start(self):
        if self._thread and self._thread.is_alive():
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="immunefleet-live", daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()

    def _run(self):
        last, owed = time.monotonic(), 0.0
        while not self._stop.is_set():
            time.sleep(0.02)
            now = time.monotonic()
            owed, last = owed + now - last, now
            ticks = 0
            while owed >= DT and ticks < 5:
                try:
                    self.step()
                except Exception as e:  # the lab must never die on stage
                    self.log(f"⚠️ simulation error: {type(e).__name__}: {e}")
                owed -= DT
                ticks += 1
            if owed > 1.0:
                owed = 0.0


_SIM, _SIM_LOCK = None, threading.Lock()


def get_sim():
    """The one shared simulation for this server process. The main screen and the attacker's device both talk to it."""
    global _SIM
    with _SIM_LOCK:
        if _SIM is None:
            _SIM = LiveSim().start()
        return _SIM
