"""The (simulated) cloud: signature check, 3-car consensus, peer testing, deployment."""
import json

import db
from signing import CLOUD_KEY, car_key, rule_key, sign

REQUIRED = 3
SAFETY_CRITICAL = {"0x0B0": "emergency braking", "0x2C0": "steering assist"}
LEGIT_IDS = {"0x244": "wheel speed", "0x3F0": "dashboard", "0x0B0": "braking", "0x2C0": "steering"}


def peer_test(rule):
    """Sandbox replay of normal driving + hard braking. Returns (verdict, final_rule, reason)."""
    tid, action, threat = rule["target_id"], rule["action"], rule["threat"]
    if tid in SAFETY_CRITICAL:
        if action == "BLOCK" and threat == "CAN_FLOOD":
            new = dict(rule, action="RATE_LIMIT")
            return "DOWNGRADE", new, f"{tid} is safety-critical ({SAFETY_CRITICAL[tid]}): BLOCK → RATE_LIMIT"
        if action == "BLOCK":
            return "FAIL", rule, f"BLOCK would drop legitimate {SAFETY_CRITICAL[tid]} frames in the hard-braking scenario"
    elif tid in LEGIT_IDS and action == "BLOCK":
        return "FAIL", rule, f"BLOCK would drop normal {LEGIT_IDS[tid]} traffic"
    return "PASS", rule, "No legitimate frames affected in normal driving or hard-braking scenarios"


class Cloud:
    def __init__(self, on_deploy=None, on_release=None, on_provisional=None, on_provisional_end=None):
        self.pending = {}    # key -> {"rule": ..., "reports": {car_id: sig}}
        self.deployed = {}   # key -> {"rule": ..., "sig": ...}
        self.events = []
        self.last_test = None
        self.on_deploy = on_deploy    # called with (rule, sig) so the fleet can start the rollout
        self.on_release = on_release  # called with car ids whose report was dropped (failed or expired)
        self.on_provisional = on_provisional          # called with (alert_rule, sig) on a first report
        self.on_provisional_end = on_provisional_end  # called when a provisional alert is withdrawn
        self.provisional = {}         # key -> {"rule": ALERT-only version, "sig": ...}
        self.fast_response = False    # off by default to strictly demonstrate 3-car consensus

        # Sync persisted antibodies from Supabase on cloud startup
        try:
            persisted = db.load_antibodies()
            if persisted:
                self.deployed.update(persisted)
                self.events.insert(0, f"☁️ Supabase: Synced {len(persisted)} active antibodies from cloud DB")
        except Exception:
            pass

    def log(self, msg):
        self.events.insert(0, msg)
        try:
            db.log_event(msg)
        except Exception:
            pass

    def has_antibody_for(self, target_id):
        return any(d["rule"]["target_id"] == target_id for d in self.deployed.values())

    def deploy_vaccine(self, rule):
        """Immediately deploys a verified virus vaccine antibody across all EV fleet vehicles."""
        k = rule_key(rule)
        self.pending.pop(k, None)
        self.provisional.pop(k, None)
        sig = sign(CLOUD_KEY, rule)
        self.deployed[k] = {"rule": rule, "sig": sig}
        try:
            db.save_antibody(rule, sig)
        except Exception:
            pass
        self.log(f"💉 FLEET VACCINE ACTIVE: Antibody deployed to all cars ({json.dumps(rule)})")
        if self.on_deploy:
            self.on_deploy(rule, sig)

    def receive(self, car_id, rule, sig):
        if sig != sign(car_key(car_id), rule):
            self.log(f"☁️ Rejected report from Car {car_id}: bad signature")
            return
        k = rule_key(rule)
        try:
            db.save_report(car_id, rule, sig)
        except Exception:
            pass
        if k in self.deployed:
            return
        entry = self.pending.setdefault(k, {"rule": rule, "reports": {}})
        entry["reports"][car_id] = sig  # the same car twice still counts once
        n = len(entry["reports"])
        self.log(f"☁️ Car {car_id} reported {k} → Pending {n}/{REQUIRED}")
        if n >= REQUIRED:
            self._test_and_deploy(k)
        elif self.fast_response and k not in self.provisional:
            self._provisional(k, entry["rule"])

    def _provisional(self, k, rule):
        """A single report never causes a hard BLOCK. It only raises ALERTs fleet-wide, and never on safety-critical IDs."""
        tid = rule["target_id"]
        if tid in SAFETY_CRITICAL:
            self.log(f"🟠 {k}: one report on a safety-critical ID ({SAFETY_CRITICAL[tid]}); not shared fleet-wide until corroborated")
            return
        prov = dict(rule, action="ALERT")
        sig = sign(CLOUD_KEY, prov)
        self.provisional[k] = {"rule": prov, "sig": sig}
        self.log(f"🟡 PROVISIONAL antibody for {k}: ALERT-only, fleet-wide, until {REQUIRED} cars corroborate")
        if self.on_provisional:
            self.on_provisional(prov, sig)

    def _withdraw_provisional(self, k):
        if self.provisional.pop(k, None):
            self.log(f"↩️ Provisional antibody for {k} withdrawn")
            if self.on_provisional_end:
                self.on_provisional_end()

    def _test_and_deploy(self, k):
        entry = self.pending.pop(k)
        self.provisional.pop(k, None)  # superseded by the full rule, or withdrawn below on failure
        verdict, final, why = peer_test(entry["rule"])
        self.last_test = {"key": k, "verdict": verdict, "why": why, "rule": final}
        self.log(f"🧪 Peer testing {k}: {verdict} ({why})")
        if verdict == "FAIL":
            self.log(f"🗑️ Rule {k} deleted")
            if self.on_provisional_end:
                self.on_provisional_end()
            if self.on_release:
                self.on_release(list(entry["reports"]))
            return
        sig = sign(CLOUD_KEY, final)
        self.deployed[rule_key(final)] = {"rule": final, "sig": sig}
        try:
            db.save_antibody(final, sig)
        except Exception:
            pass
        self.log(f"✅ CONSENSUS REACHED: ANTIBODY DEPLOYED ({json.dumps(final)})")
        if self.on_deploy:
            self.on_deploy(final, sig)

    def expire_stuck(self):
        """Rules that never reach consensus eventually expire and are deleted."""
        stuck = [k for k, e in self.pending.items() if len(e["reports"]) < REQUIRED]
        for k in stuck:
            reporters = list(self.pending.pop(k)["reports"])
            self.log(f"⌛ Pending rule {k} expired at {len(reporters)}/{REQUIRED} and was deleted")
            self._withdraw_provisional(k)
            if self.on_release:
                self.on_release(reporters)
        return len(stuck)
