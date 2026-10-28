"""Streamlit side of the live attack lab. app.py needs three things from here:

    is_attacker_view()          True when the page was opened as  ...?role=attacker  (a teammate's device)
    render_attacker_console()   the attacker's controls and live feedback; app.py then calls st.stop()
    render_live_defense()       the live panel for the main screen

The simulation itself lives in live.py. Both views read and write the same shared simulation in this server process,
so an attack launched on one device shows up on the other within a second.
"""
import html as H
import socket

import streamlit as st

from live import HIST, N_CARS, get_sim

REFRESH_S = 1.0
KINDS = ["DoS flood (an ID that is never used)", "Injection (spoof a real ECU's ID)"]


def esc(x):
    return H.escape(str(x))


def flat(s):
    """Collapse multi-line HTML so Streamlit's markdown parser never sees blank or indented lines."""
    return "".join(line.strip() for line in s.splitlines())


def _fragment(every=None):
    """st.fragment re-runs only this piece (every N seconds). Falls back to a plain function on old Streamlit."""
    def wrap(fn):
        frag = getattr(st, "fragment", None)
        if frag is None:
            return fn
        try:
            return frag(run_every=every)(fn) if every else frag(fn)
        except TypeError:  # Streamlit older than 1.37 has no run_every
            return frag(fn)
    return wrap


# ---------------------------------------------------------------- styles
LIVE_CSS = """<style>
.st-key-live_ctl,.st-key-live_att{background:linear-gradient(145deg,rgba(40,14,26,.62),rgba(12,4,9,.52))!important;backdrop-filter:blur(16px) saturate(140%);border:1px solid rgba(232,160,191,.28)!important;border-radius:22px!important;box-shadow:0 22px 50px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.07);padding:18px 22px}
.lv-banner{--m:var(--grn);display:inline-flex;align-items:center;gap:10px;padding:8px 20px;border-radius:30px;border:1px solid var(--m);background:rgba(8,3,7,.6);font:700 15px var(--sans);color:var(--m)}
.lv-banner.on{--m:var(--red)}.lv-banner.def{--m:var(--cy)}
.lv-banner i{width:10px;height:10px;border-radius:50%;background:var(--m);box-shadow:0 0 12px var(--m)}
.lv-banner.on i{animation:lvblink 1s ease-in-out infinite}
@keyframes lvblink{50%{opacity:.3}}
.lv-cars{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin:16px 0}
.lvcar{--c:var(--grn);padding:14px 12px 12px;border-radius:20px;background:linear-gradient(160deg,rgba(34,11,22,.72),rgba(8,3,7,.62));backdrop-filter:blur(14px);border:1.5px solid color-mix(in srgb,var(--c) 70%,transparent);box-shadow:0 0 22px color-mix(in srgb,var(--c) 24%,transparent),inset 0 0 28px color-mix(in srgb,var(--c) 8%,transparent)}
.lvcar.s-compromised{--c:var(--red)}.lvcar.s-contained{--c:var(--amb)}.lvcar.s-immune,.lvcar.s-blocked{--c:var(--cy)}
.lvhead{display:flex;justify-content:space-between;align-items:baseline;gap:6px}
.lvhead b{font:700 17px var(--serif);color:#fff}
.lvstate{font:700 11.5px var(--sans);letter-spacing:.04em;color:var(--c);text-align:right}
.lv-spark{width:100%;height:38px;display:block;margin:8px 0 4px}
.lv-spark .base{stroke:rgba(255,255,255,.14);stroke-width:1}
.lv-spark .fill{fill:rgba(255,45,85,.18)}.lv-spark .inn{fill:none;stroke:#ff2d55;stroke-width:1.6;stroke-linejoin:round}
.lv-spark .out{fill:none;stroke:#22d3ff;stroke-width:1.8;stroke-linejoin:round}
.lvnums{font:500 12px ui-monospace,Menlo,Consolas,monospace;opacity:.85}
.lvnote{font-size:12px;opacity:.75;min-height:32px;line-height:1.3;margin-top:4px}
.lvkey{display:flex;gap:16px;font:500 12px var(--sans);opacity:.75;margin:-4px 0 6px;flex-wrap:wrap}
.lvkey span::before{content:"";display:inline-block;width:14px;height:3px;border-radius:2px;margin-right:6px;vertical-align:middle;background:#ff2d55}
.lvkey span.o::before{background:#22d3ff}
.lv-two{display:grid;grid-template-columns:1fr 1.25fr;gap:18px;align-items:start}
.lv-row{margin-top:12px;padding:11px 14px;border-radius:14px;border:1px solid color-mix(in srgb,var(--rc,#e8a0bf) 55%,transparent);background:color-mix(in srgb,var(--rc,#e8a0bf) 9%,transparent)}
.lv-row.p{--rc:var(--pink)}.lv-row.b{--rc:var(--cy)}.lv-row.o{--rc:var(--grn)}.lv-row.y{--rc:var(--yel)}.lv-row.x{--rc:var(--red)}
.lv-row code{background:rgba(0,0,0,.4);color:#fff;padding:1px 6px;border-radius:6px}
.lv-feed{font:500 12.5px/1.55 ui-monospace,Menlo,Consolas,monospace;max-height:330px;overflow:auto}
.lv-feed div{padding:3px 0;border-bottom:1px dashed rgba(232,160,191,.12)}
.lv-t{opacity:.5;margin-right:8px}
.tile .lv-sub{display:block;font:500 11.5px var(--sans);opacity:.7;margin-top:2px;letter-spacing:0;text-transform:none}
.lv-verdict{margin:12px 0;padding:14px 18px;border-radius:16px;border:1px solid var(--vc,var(--pink));background:color-mix(in srgb,var(--vc,var(--pink)) 10%,rgba(8,3,7,.6));font:600 16px var(--sans)}
.lv-verdict.on{--vc:var(--red)}.lv-verdict.def{--vc:var(--cy)}.lv-verdict.mid{--vc:var(--amb)}
@media(max-width:900px){.lv-cars{grid-template-columns:repeat(2,1fr)}.lv-two{grid-template-columns:1fr}}
</style>"""

# the attacker's page is shown instead of the whole app, so it carries the same look by itself
ATTACKER_CSS = """<style>
@import url('https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,800&family=Chakra+Petch:wght@400;500;600;700&family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&display=swap');
:root{--bg:#07020a;--pink:#e8a0bf;--cy:#22d3ff;--red:#ff2d55;--grn:#2dffa0;--amb:#ffa31a;--yel:#ffd23f;--ink:#f6dce8;
--serif:'Fraunces',Georgia,serif;--sans:'Chakra Petch','Segoe UI',system-ui,sans-serif}
html,body,.stApp{background:var(--bg)!important}
[data-testid=stAppViewContainer],[data-testid=stHeader]{background:transparent!important}
#MainMenu,footer{visibility:hidden}
.stApp,.stApp p,.stApp label,.stApp span:not([data-testid*="Icon"]):not([data-testid*="icon"]):not([class*="material-symbols"]):not([class*="material-icons"]):not([class*="stExpanderToggleIcon"]),.stApp li{font-family:var(--sans);color:var(--ink)}
[data-testid*="Icon"],[data-testid*="icon"],[class*="material-symbols"],[class*="material-icons"],[data-testid="stExpanderToggleIcon"]{font-family:'Material Symbols Rounded','Material Symbols Outlined','Material Icons',sans-serif!important;font-feature-settings:'liga' 1!important;letter-spacing:normal!important;text-transform:none!important}
.block-container{position:relative;z-index:1;max-width:1100px;padding-top:1.2rem}
[data-testid=stElementContainer]:has(.atkbg){position:absolute;width:0;height:0;margin:0}
.atkbg{position:fixed;inset:0;z-index:-1;overflow:hidden;pointer-events:none}
.atkbg .mesh{position:absolute;inset:-20%;background:radial-gradient(40% 40% at 20% 30%,rgba(255,45,85,.26),transparent 70%),radial-gradient(35% 35% at 80% 20%,rgba(232,60,130,.2),transparent 70%),radial-gradient(45% 45% at 60% 85%,rgba(120,20,70,.38),transparent 70%)}
.atkbg .grid{position:absolute;left:-50%;right:-50%;bottom:0;height:55%;background-image:linear-gradient(rgba(255,45,85,.16) 1px,transparent 1px),linear-gradient(90deg,rgba(232,160,191,.12) 1px,transparent 1px);background-size:64px 64px;transform:perspective(420px) rotateX(62deg);transform-origin:bottom;-webkit-mask-image:linear-gradient(transparent,#000 70%);mask-image:linear-gradient(transparent,#000 70%)}
.atknav{display:flex;align-items:center;gap:14px;padding:12px 26px;border:1.5px solid #ff5d7d;border-radius:26px 26px 60px 26px;background:rgba(10,3,8,.72);backdrop-filter:blur(14px);font:600 20px var(--serif);color:#fff}
.atknav small{font:600 13px var(--sans);color:#ff9fb3;margin-left:auto;letter-spacing:.06em;text-transform:uppercase}
.sec{font:600 clamp(26px,3.2vw,38px)/1.1 var(--serif);color:#fff;margin:26px 0 4px}
.secsub{opacity:.75;margin:0 0 14px;font-size:15px}
.glass{background:linear-gradient(145deg,rgba(40,14,26,.62),rgba(12,4,9,.52));backdrop-filter:blur(16px);border:1px solid rgba(232,160,191,.28);border-radius:22px;padding:18px 22px}
.tiles{display:flex;gap:10px;flex-wrap:wrap}
.tile{flex:1;min-width:130px;padding:10px 14px;border-radius:14px;border:1px solid rgba(34,211,255,.5);background:rgba(34,211,255,.08)}
.tile small{display:block;opacity:.75;font:700 11px var(--sans);letter-spacing:.08em;text-transform:uppercase}
.tile b{font:700 17px ui-monospace,Menlo,Consolas,monospace;color:#fff;word-break:break-all}
.stButton>button{background:rgba(20,8,14,.62);color:var(--ink);border:1px solid rgba(232,160,191,.42);border-radius:14px 14px 24px 14px;font:600 15px var(--sans);transition:all .25s}
.stButton>button:hover{border-color:var(--pink);color:#fff;box-shadow:0 0 24px rgba(232,160,191,.42)}
.st-key-atk_go button{border-color:var(--red);background:linear-gradient(135deg,rgba(255,45,85,.42),rgba(20,6,12,.9));min-height:3.2rem}
.st-key-atk_go button p{font:700 17px var(--sans);color:#fff}
.st-key-atk_go button:hover{box-shadow:0 0 34px rgba(255,45,85,.6);border-color:var(--red)}
</style>"""


def _background():
    return "<div class='atkbg'><div class='mesh'></div><div class='grid'></div></div>"


# ---------------------------------------------------------------- html pieces
LABEL = {"healthy": "HEALTHY", "compromised": "UNDER ATTACK", "contained": "CONTAINED (LOCAL)", "immune": "IMMUNE", "blocked": "ATTACK BLOCKED"}


def spark(hist):
    """Last 40 s of one car's traffic on the attacked ID: red = arriving, cyan = what got through the gateway."""
    w, h, pts = 170.0, 38.0, list(hist)[-HIST:]
    base = f"<line class='base' x1='0' y1='{h - 2}' x2='{w}' y2='{h - 2}'/>"
    if not pts:
        return f"<svg class='lv-spark' viewBox='0 0 {w:.0f} {h:.0f}'>{base}</svg>"
    peak, n, step = max(max(a for a, _ in pts), 1.0), len(pts), w / (HIST - 1)
    xs = [w - (n - 1 - i) * step for i in range(n)]
    y = lambda v: h - 2 - (h - 6) * v / peak
    inn = " ".join(f"{x:.1f},{y(a):.1f}" for x, (a, _) in zip(xs, pts))
    out = " ".join(f"{x:.1f},{y(b):.1f}" for x, (_, b) in zip(xs, pts))
    return (f"<svg class='lv-spark' viewBox='0 0 {w:.0f} {h:.0f}'>{base}<polygon class='fill' points='{xs[0]:.1f},{h - 2} {inn} {xs[-1]:.1f},{h - 2}'/>"
            f"<polyline class='inn' points='{inn}'/><polyline class='out' points='{out}'/></svg>")


def car_tile(c):
    s, note = c["status"], ""
    if s == "healthy":
        note = "No anomaly on the bus"
    elif s == "compromised":
        note = "Under attack, no defense yet" if c["rate_in"] else "Under attack"
    elif s == "contained":
        note = f"Own antibody: {', '.join(c['rules'])}"
    elif s == "immune":
        note = "Fleet antibody applied (signature verified)"
    elif s == "blocked":
        note = f"Dropping {100 * c['atk_drop'] / c['atk_in']:.0f}% of attack frames" if c["atk_in"] else "Fleet antibody active"
    if c["detect_delay"] is not None:
        note += f" · detected in {c['detect_delay']:.1f}s"
    return flat(f"""<div class="lvcar s-{s}"><div class="lvhead"><b>Car {c['id']}</b><span class="lvstate">{LABEL[s]}</span></div>
{spark(c['hist'])}<div class="lvnums">in {c['rate_in']:,.0f}/s · through {c['rate_pass']:,.0f}/s</div><div class="lvnote">{esc(note)}</div></div>""")


def attack_text(a):
    what = "DoS flood on ID 0x000" if a["kind"] == "dos" else f"injection on ID 0x{a['target']:03X}"
    return f"{what} · {a['rate']:,} frames/s · Car {', '.join(map(str, a['cars']))}"


def banner(snap):
    a, cars = snap["attack"], snap["cars"]
    hit = [c for c in cars if c["id"] in a["cars"]]
    if a["on"] and hit and all(c["fleet"] for c in hit):
        return f"<div class='lv-banner def'><i></i>ATTACK LIVE, BEING BLOCKED · {esc(attack_text(a))}</div>"
    if a["on"]:
        return f"<div class='lv-banner on'><i></i>ATTACK LIVE · {esc(attack_text(a))}</div>"
    return "<div class='lv-banner'><i></i>No attack right now. Waiting for the attacker.</div>"


def tiles(snap):
    m, ro = snap["metrics"], snap["rollout"]
    if m["protect_s"] is not None:
        protect, sub = f"{m['protect_s']:.1f} s", "first attack frame to every car immune"
    elif ro:
        protect, sub = f"stage {ro['stage']}/{ro['of']}", "rolling out"
    elif snap["pending"]:
        protect, sub = "waiting", f"{snap['pending'][0]['n']}/3 cars have reported"
    else:
        protect, sub = "n/a", "no antibody yet"
    det = f"{m['detect_s']:.1f} s" if m["detect_s"] is not None else "n/a"
    blocked = f"{m['blocked_pct']:.1f}%" if m["blocked_pct"] is not None else "n/a"
    items = [("Detection time", det, "fastest car, on-car statistics"), ("Fleet protected in", protect, sub),
             ("Attack frames blocked", blocked, f"of {m['attack_frames']:,.0f} sent (includes the leak before detection)"),
             ("Legit traffic lost", f"{m['legit_lost_pct']:.2f}%", f"of {m['legit_frames']:,.0f} real frames")]
    return "<div class='tiles'>" + "".join(f"<div class='tile'><small>{esc(k)}</small><b>{esc(v)}</b><span class='lv-sub'>{esc(s)}</span></div>" for k, v, s in items) + "</div>"


def cloud_card(snap):
    rows = []
    for p in snap["pending"]:
        pips = "".join(f"<i class='pip{' on' if j < p['n'] else ''}'></i>" for j in range(3))
        rows.append(f"<div class='lv-row p'><b>Pending</b> <code>{esc(p['key'])}</code> {p['n']}/3 cars agree<div class='pips'>{pips}</div></div>")
    if snap["last_test"]:
        t = snap["last_test"]
        cls = {"PASS": "o", "DOWNGRADE": "y"}.get(t["verdict"], "x")
        rows.append(f"<div class='lv-row {cls}'><b>Peer test {esc(t['key'])}: {esc(t['verdict'])}</b><br>{esc(t['why'])}</div>")
    ro = snap["rollout"]
    if ro:
        segs = "".join(f"<u class='{'on' if j < ro['stage'] else ''}'></u>" for j in range(ro["of"]))
        rows.append(f"<div class='lv-row b'><b>Staged rollout</b> stage {ro['stage']} of {ro['of']}<div class='stages'>{segs}</div></div>")
    for d in snap["deployed"]:
        rows.append(f"<div class='lv-row b'><b>Deployed</b> <code>{esc(d['key'])}</code> {esc(d['rule']['action'])}<br><small>cloud signature <code>{esc(d['sig'])}</code></small></div>")
    body = "".join(rows) or "<div style='opacity:.7;margin-top:12px'>No rules yet. The vote starts when a car reports an attack.</div>"
    return f"<div class='glass cons'><h3>Cloud consensus</h3><span style='opacity:.75;font-size:14px'>3 of 5 cars must agree before the fleet is told to block.</span>{body}</div>"


def feed_card(snap):
    lines = "".join(f"<div><span class='lv-t'>{t:6.1f}s</span>{esc(m)}</div>" for t, m in snap["events"]) or "<div>Quiet.</div>"
    return f"<div class='glass lv-feed'>{lines}</div>"


# ---------------------------------------------------------------- attacker device
def is_attacker_view():
    """True for the page opened as  http://<host>:8501/?role=attacker"""
    try:
        return str(st.query_params.get("role", "")).lower() == "attacker"
    except Exception:
        return False


def _go():
    ss = st.session_state
    kind = "dos" if ss.get("atk_kind", KINDS[0]) == KINDS[0] else "inject"
    get_sim().set_attack(on=True, kind=kind, rate=ss.get("atk_rate", 3000), cars=ss.get("atk_cars", [1]),
                         target=int(ss.get("atk_target", "0x316"), 16))


def _preset(n):
    st.session_state["atk_cars"] = list(range(1, n + 1))


def _verdict(snap):
    a = snap["attack"]
    hit = [c for c in snap["cars"] if c["id"] in a["cars"]]
    if not a["on"]:
        return "mid", "Attack stopped. Change the settings and launch again."
    if hit and all(c["fleet"] for c in hit):
        return "def", "🛡️ DEFENDED. Every car you hit already holds the fleet antibody and drops your frames."
    if any(c["status"] == "contained" for c in hit):
        return "mid", "🟠 The cars you hit are containing you locally. The fleet only learns after 3 cars report."
    if any(c["detect_delay"] for c in hit):
        return "mid", "🟠 Detected. Defenses are spinning up."
    return "on", "💥 Your frames are landing. No defense has reacted yet."


@_fragment(REFRESH_S)
def _attacker_feedback():
    snap = get_sim().snapshot()
    cls, text = _verdict(snap)
    a = snap["attack"]
    hit = [c for c in snap["cars"] if c["id"] in a["cars"]]
    sent = sum(c["atk_in"] for c in hit)
    dropped = sum(c["atk_drop"] for c in hit)
    pct = f"{100 * dropped / sent:.1f}%" if sent else "n/a"
    st.markdown(f"<div class='lv-verdict {cls}'>{esc(text)}</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='tiles'><div class='tile'><small>Frames you sent</small><b>{sent:,.0f}</b></div>"
                f"<div class='tile'><small>Frames dropped</small><b>{dropped:,.0f}</b></div>"
                f"<div class='tile'><small>Blocked</small><b>{pct}</b></div></div>", unsafe_allow_html=True)
    st.markdown("<div class='lvkey'><span>frames arriving</span><span class='o'>frames that got through</span></div>", unsafe_allow_html=True)
    st.markdown("<div class='lv-cars'>" + "".join(car_tile(c) for c in hit) + "</div>" if hit else "", unsafe_allow_html=True)


def render_attacker_console():
    st.markdown(ATTACKER_CSS + LIVE_CSS + _background(), unsafe_allow_html=True)
    st.markdown("<div class='atknav'>🕶️ ImmuneFleet<small>attacker console</small></div>", unsafe_allow_html=True)
    st.markdown("<h2 class='sec'>Attack the fleet</h2><p class='secsub'>Whatever you launch here hits the cars on the main screen, live. "
                "Try to get a frame through.</p>", unsafe_allow_html=True)
    snap = get_sim().snapshot()
    with st.container(border=True, key="live_att"):
        st.radio("Attack type", KINDS, key="atk_kind")
        if st.session_state.get("atk_kind", KINDS[0]) != KINDS[0]:
            ids = [f"0x{i:03X}" for i in snap["known_ids"]]
            st.selectbox("ID to spoof (a real ECU on this car)", ids, index=ids.index("0x316") if "0x316" in ids else 0, key="atk_target")
        st.slider("Frames per second", 10, 6000, 3000, step=10, key="atk_rate",
                  help="The public HCRL DoS recording floods about 3,300 frames/s. Very low rates may slip under the detector.")
        st.multiselect("Cars to hit", list(range(1, N_CARS + 1)), default=[1], key="atk_cars", format_func=lambda i: f"Car {i}")
        p = st.columns(3)
        p[0].button("Just Car 1", on_click=_preset, args=(1,), use_container_width=True, key="atk_p1")
        p[1].button("Cars 1 to 3", on_click=_preset, args=(3,), use_container_width=True, key="atk_p3")
        p[2].button("Whole fleet", on_click=_preset, args=(5,), use_container_width=True, key="atk_p5")
        g = st.columns([2, 1])
        g[0].button("🚀 Launch or update attack", on_click=_go, use_container_width=True, key="atk_go")
        g[1].button("⏹ Stop", on_click=lambda: get_sim().set_attack(on=False), use_container_width=True, key="atk_stop")
    _attacker_feedback()


# ---------------------------------------------------------------- main screen
def lan_ip():
    """The address a teammate's device can use. Connecting a UDP socket sends nothing; it just picks the right interface."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "<this-computer-ip>"


def attacker_url():
    try:
        port = st.get_option("server.port") or 8501
    except Exception:
        port = 8501
    return f"http://{lan_ip()}:{port}/?role=attacker"


def _solo(n):
    get_sim().set_attack(on=True, kind="dos", rate=3000, cars=list(range(1, n + 1)))


@_fragment()
def _controls():
    sim = get_sim()
    with st.container(border=True, key="live_ctl"):
        left, right = st.columns([2.4, 3], gap="large")
        with left:
            st.markdown("**A teammate attacks from another device**")
            st.code(attacker_url(), language="text")
            st.caption("Same Wi-Fi. Start Streamlit with `--server.address 0.0.0.0` so other devices can reach it.")
        with right:
            st.markdown("**Or attack from here**")
            b = st.columns(4)
            b[0].button("💥 Hack 1 car", key="live_a1", on_click=_solo, args=(1,), use_container_width=True)
            b[1].button("💥 Hack 3 cars", key="live_a3", on_click=_solo, args=(3,), use_container_width=True)
            b[2].button("⏹ Stop attack", key="live_stop", on_click=lambda: sim.set_attack(on=False), use_container_width=True)
            b[3].button("↺ Reset lab", key="live_reset", on_click=sim.reset, use_container_width=True)
            st.caption("The lab keeps running by itself. Hack 1 car: it contains itself but the fleet waits for quorum. Hack 3 cars: the fleet is protected.")


@_fragment(REFRESH_S)
def _live_view():
    snap = get_sim().snapshot()
    st.markdown(banner(snap), unsafe_allow_html=True)
    st.markdown(f"<div style='height:12px'></div>{tiles(snap)}", unsafe_allow_html=True)
    st.markdown("<div class='lvkey' style='margin-top:14px'><span>frames arriving at the car</span><span class='o'>frames that got through its gateway</span></div>"
                "<div class='lv-cars'>" + "".join(car_tile(c) for c in snap["cars"]) + "</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='lv-two'>{cloud_card(snap)}{feed_card(snap)}</div>", unsafe_allow_html=True)
    src = "a real recording from data/" if snap["real_data"] else "synthetic ECU traffic (put normal_run_data.txt in data/ to use a real recording)"
    st.caption(f"Normal traffic: {src}. Detection, validation, signatures, voting, peer test and rollout are the real code; the attack and the CAN frames are simulated.")


def render_live_defense():
    get_sim()
    st.markdown(LIVE_CSS, unsafe_allow_html=True)
    st.markdown("<h2 class='sec' id='live'>Live attack lab</h2><p class='secsub'>Five cars, one shared bus simulation. "
                "Launch an attack and watch detection, consensus and protection happen in real time.</p>", unsafe_allow_html=True)
    _controls()
    _live_view()
