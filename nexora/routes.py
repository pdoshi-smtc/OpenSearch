"""
routes.py
"""
import json
import os
import re
import threading
from datetime import datetime, timedelta
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from .jsm_ticket import create_jsm_ticket

from flask import Blueprint, render_template, request, jsonify

nexora_bp = Blueprint(
    "nexora",
    __name__,
    template_folder="templates",
    static_folder="static",
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_JSON = os.path.join(ROOT, "data", "data.json")
ALERTS_JSON = os.path.join(ROOT, "data", "alerts.json")
COVERAGE_DATA_JSON = os.path.join(ROOT, "data", "coverage data.json")

_hits_lock = threading.Lock()
_cached_hits: Optional[List[dict]] = None
_coverage_lock = threading.Lock()
_cached_coverage: Optional[List[dict]] = None

MAX_OPENSEARCH_EVENTS = 20000

# Minimal country → MCC (mobile country code) prefix for filtering OpenSearch docs
COUNTRY_MCC_PREFIX: Dict[str, str] = {
    "sweden": "240",
    "france": "208",
    "germany": "262",
    "united kingdom": "234",
    "uk": "234",
    "spain": "214",
    "italy": "222",
    "netherlands": "204",
    "belgium": "206",
    "norway": "242",
    "denmark": "238",
    "finland": "244",
    "poland": "260",
    "usa": "310",
    "united states": "310",
    "canada": "302",
    "japan": "440",
    "australia": "505",
    "india": "404",
}

COVERAGE_HINTS: Dict[str, Dict[str, Any]] = {
    "hig3": {
        "label": "HiG3",
        "rat_types": ["LTE", "4G", "NB-IoT"],
        "typical_sponsors": ["Global Roaming Partner A", "EU Wholesale B"],
        "region": "EMEA + Americas",
        "notes": "Gateway cluster; check sponsor handover timers on degraded attach.",
    },
    "emea1": {
        "label": "EMEA-1",
        "rat_types": ["2G", "3G", "4G"],
        "typical_sponsors": ["National MNO X", "Roaming Hub Y"],
        "region": "Europe",
        "notes": "Legacy CSFB paths; correlate with maintenance windows.",
    },
}

NETWORK_RE = re.compile(r"\b([A-Za-z]{2,8}\d{1,2})\b", re.IGNORECASE)
PRODUCT_CODE_RE = re.compile(
    r"\b(?:PRD|FW|VER|CODE)[\s:-]*([A-Z0-9][A-Z0-9._-]{2,14})\b", re.IGNORECASE
)
LOOSE_CODE_RE = re.compile(r"\b([A-Z0-9]{4,12})\b")
CODE_STOPWORDS = {
    "ISSUE", "SEING", "SEEING", "HELP", "DOWN", "LOST", "FROM", "WITH",
    "THAT", "THIS", "WHAT", "WHEN", "TEAM", "NODE", "SITE", "AREA",
    "TRUE", "FALSE", "HTTP", "HTTPS", "JSON", "LTE", "GSM", "CALL",
}

VPLMN_ALERT_RE = re.compile(r"-\s*(.*?)\s*\[", re.DOTALL)


def _normalize_net(token: str) -> str:
    return re.sub(r"[^a-z0-9]", "", token.lower())


def extract_network_names(text: str) -> List[str]:
    found = []
    for m in NETWORK_RE.finditer(text or ""):
        t = m.group(1)
        key = _normalize_net(t)
        if key in COVERAGE_HINTS or len(t) >= 3:
            found.append(t)
    seen = set()
    out = []
    for x in found:
        k = x.upper()
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out[:5]


def extract_product_code(text: str) -> Optional[str]:
    m = PRODUCT_CODE_RE.search(text or "")
    if m:
        return m.group(1).strip()
    m2 = LOOSE_CODE_RE.search((text or "").upper())
    if m2:
        g = m2.group(1)
        if g not in CODE_STOPWORDS:
            return g
    return None


def coverage_context_for_network(net_tokens: List[str]) -> Dict[str, Any]:
    blocks = []
    for t in net_tokens:
        key = _normalize_net(t)
        hint = COVERAGE_HINTS.get(key)
        if hint:
            blocks.append({"token": t, **hint})
        else:
            blocks.append(
                {
                    "token": t,
                    "label": t.upper(),
                    "rat_types": ["2G", "3G", "4G", "5G"],
                    "typical_sponsors": ["(from coverage file)"],
                    "region": "—",
                    "notes": "Map this network name to your coverage export for RAT and sponsor columns.",
                }
            )
    return {"networks": blocks}


def country_to_mcc_prefix(country: str) -> Optional[str]:
    if not country or not country.strip():
        return None
    k = country.strip().lower()
    return COUNTRY_MCC_PREFIX.get(k)


def get_cached_hits() -> List[dict]:
    global _cached_hits
    with _hits_lock:
        if _cached_hits is None:
            if not os.path.isfile(DATA_JSON):
                _cached_hits = []
            else:
                with open(DATA_JSON, "r", encoding="utf-8", errors="ignore") as f:
                    blob = json.load(f)
                _cached_hits = blob.get("hits", {}).get("hits", []) or []
        return _cached_hits


def _norm_txt(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def get_coverage_rows() -> List[dict]:
    global _cached_coverage
    with _coverage_lock:
        if _cached_coverage is None:
            if not os.path.isfile(COVERAGE_DATA_JSON):
                _cached_coverage = []
            else:
                with open(COVERAGE_DATA_JSON, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                _cached_coverage = data if isinstance(data, list) else []
        return _cached_coverage


def build_coverage_file_report(
    country: str,
    network: str,
    sponsor: str,
    symptoms: str,
) -> Dict[str, Any]:
    """
    Match `data/coverage data.json` rows by country / network / sponsor (any subset).
    Suggest alternate networks and sponsors in the same country when the primary path looks impaired.
    """
    rows = get_coverage_rows()
    if not rows:
        return {
            "source_found": False,
            "matches": 0,
            "narrative": "**Coverage file** (`data/coverage data.json`) not found or empty — Nexora cannot validate roaming rows from the export.",
            "alternate_networks": [],
            "alternate_sponsors": [],
            "product_versions_top": [],
            "availability_yes": 0,
            "availability_no": 0,
        }

    c_needle = _norm_txt(country)
    n_needle = _norm_txt(network)
    s_needle = _norm_txt(sponsor)

    def row_matches(r: dict) -> bool:
        rc = _norm_txt(str(r.get("country", "")))
        rn = _norm_txt(str(r.get("Network", "")))
        rs = _norm_txt(str(r.get("Roaming Sponsors", "")))
        if c_needle and c_needle not in rc and rc not in c_needle:
            return False
        if n_needle and n_needle not in rn and rn not in n_needle:
            # allow HiG3 vs Hi3G style: collapse digit 3
            nflat = n_needle.replace("3", "").replace("g", "")
            rnflat = rn.replace("3", "").replace("g", "")
            if nflat and nflat not in rnflat:
                return False
        if s_needle and s_needle not in rs:
            return False
        return True

    matched: List[dict] = []
    for r in rows:
        if row_matches(r):
            matched.append(r)
            if len(matched) >= 5000:
                break

    pv = Counter()
    avail_yes = avail_no = 0
    for r in matched:
        pv[str(r.get("Product version", "")).strip() or "(unknown)"] += 1
        av = _norm_txt(str(r.get("Available", "")))
        if av == "yes":
            avail_yes += 1
        elif av == "no":
            avail_no += 1

    country_anchor = c_needle or (
        _norm_txt(str(matched[0].get("country", ""))) if matched else ""
    )
    same_country: List[dict] = []
    if country_anchor:
        for r in rows:
            rc = _norm_txt(str(r.get("country", "")))
            if country_anchor not in rc and rc not in country_anchor:
                continue
            same_country.append(r)
            if len(same_country) >= 12000:
                break

    alt_nets: set = set()
    alt_sponsors: set = set()
    for r in same_country:
        if _norm_txt(str(r.get("Available", ""))) != "yes":
            continue
        alt_nets.add(str(r.get("Network", "")).strip())
        alt_sponsors.add(str(r.get("Roaming Sponsors", "")).strip())

    primary_nets = {str(r.get("Network", "")).strip() for r in matched if str(r.get("Network", "")).strip()}
    primary_norm = {_norm_txt(pn) for pn in list(primary_nets)[:12]}
    alt_nets = {an for an in alt_nets if _norm_txt(an) not in primary_norm}

    alt_nets_l = sorted(x for x in alt_nets if x)[:18]
    alt_sp_l = sorted(x for x in alt_sponsors if x)[:22]

    lines: List[str] = []
    lines.append(
        f"**Coverage export:** {len(matched)} row(s) matched your filters (country / network / sponsor)."
    )
    if matched:
        blocked = Counter(
            str(r.get("Who blocked", "")).strip() or "—" for r in matched[:800]
        )
        top_blk = blocked.most_common(4)
        if top_blk:
            lines.append("**Who blocked (sample):** " + ", ".join(f"{k}: {v}" for k, v in top_blk))
        lines.append(
            f"**Availability in matched slice:** Yes ≈ **{avail_yes}** rows, No ≈ **{avail_no}** rows "
            "(multiple product builds can repeat the same PLMN)."
        )
    else:
        lines.append(
            "Nexora did **not** find a direct row match — try a fuller **network** name from the coverage sheet "
            "or the **country** exactly as in the file."
        )

    if alt_nets_l:
        lines.append(
            "**Other networks in the same country with `Available: Yes` (failover ideas):** "
            + ", ".join(f"`{x}`" for x in alt_nets_l[:12])
        )
    if alt_sp_l:
        lines.append(
            "**Sponsors seen on available rows in that country:** "
            + ", ".join(f"`{x}`" for x in alt_sp_l[:14])
        )

    pv_top = pv.most_common(10)

    return {
        "source_found": True,
        "matches": len(matched),
        "narrative": "\n\n".join(lines),
        "alternate_networks": alt_nets_l,
        "alternate_sponsors": alt_sp_l,
        "product_versions_top": [[k, v] for k, v in pv_top],
        "availability_yes": avail_yes,
        "availability_no": avail_no,
    }


def load_alerts() -> List[dict]:
    if not os.path.isfile(ALERTS_JSON):
        return []
    with open(ALERTS_JSON, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
    return data.get("alerts", []) or []


def find_alert_by_tiny_id(tiny_id: str) -> Optional[dict]:
    tid = (tiny_id or "").strip()
    if not tid:
        return None
    for a in load_alerts():
        if str(a.get("tinyId", "")).strip() == tid:
            return a
    return None


def extract_vplmn_from_alert_message(message: str) -> Optional[str]:
    if not message:
        return None
    m = VPLMN_ALERT_RE.search(message)
    if m:
        return m.group(1).strip()
    return None


def parse_alert_center_time(alert: dict) -> Optional[datetime]:
    s = alert.get("createdAt_readable") or alert.get("lastOccuredAt_readable")
    if not s:
        return None
    s = str(s).replace(" UTC", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S UTC"):
        try:
            return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return None


def parse_doc_timestamp(doc: dict) -> Optional[datetime]:
    raw = doc.get("timestamp") or doc.get("Event-Timestamp")
    if not raw:
        return None
    s = str(raw).replace("Z", "")[:19]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s[:19], fmt)
        except ValueError:
            continue
    return None


def vplmn_matches(doc_vplmn: str, needle: str) -> bool:
    if not needle or not needle.strip():
        return True
    d = (doc_vplmn or "").strip().lower()
    n = needle.strip().lower()
    return n in d or d in n


def sponsor_matches(doc_partner: str, needle: str) -> bool:
    if not needle or not needle.strip():
        return True
    d = (doc_partner or "").strip().lower()
    n = needle.strip().lower()
    return n in d or d in n


def mcc_matches(doc_mcc: str, prefix: Optional[str]) -> bool:
    if not prefix:
        return True
    m = (doc_mcc or "").strip()
    return m.startswith(prefix)


def analyze_opensearch_correlation(
    center: datetime,
    vplmn_needle: str,
    sponsor_needle: str,
    mcc_prefix: Optional[str],
    symptoms: str,
) -> Dict[str, Any]:
    hits = get_cached_hits()
    window_start = center - timedelta(hours=1)
    window_end = center + timedelta(hours=1)
    prev_start = window_start - timedelta(days=1)
    prev_end = window_end - timedelta(days=1)

    sym = (symptoms or "").lower()
    focus_lost = "lost" in sym and "service" in sym
    focus_lu = any(x in sym for x in ("location", "ulr", "tau", "location update"))

    def window_stats(start: datetime, end: datetime) -> Dict[str, Any]:
        result_counts: Dict[str, int] = {}
        procedures: Dict[str, int] = {}
        customers: set = set()
        partners: set = set()
        imsis: set = set()
        iccids: set = set()
        sim_versions: Counter[str] = Counter()
        service_types: Counter[str] = Counter()
        sim_status: Counter[str] = Counter()
        n = 0
        capped = False
        for item in hits:
            if n >= MAX_OPENSEARCH_EVENTS:
                capped = True
                break
            doc = item.get("_source", {}).get("doc", {})
            if not vplmn_matches(doc.get("vplmn", ""), vplmn_needle):
                continue
            if not sponsor_matches(doc.get("roaming_partner", ""), sponsor_needle):
                continue
            if not mcc_matches(str(doc.get("mcc", "")), mcc_prefix):
                continue
            ts = parse_doc_timestamp(doc)
            if ts is None or not (start <= ts <= end):
                continue
            rd = (doc.get("result_detail") or "").strip() or "(empty)"
            if focus_lost and rd.lower() != "lost-service":
                continue
            if focus_lu:
                proc_u = (doc.get("procedure") or "").upper()
                if proc_u not in ("ULR", "AIR", "TAU", "ULA"):
                    continue
            n += 1
            result_counts[rd] = result_counts.get(rd, 0) + 1
            proc = doc.get("procedure") or "(none)"
            procedures[proc] = procedures.get(proc, 0) + 1
            cn = (doc.get("customer_name") or "").strip()
            if cn:
                customers.add(cn)
            rp = (doc.get("roaming_partner") or "").strip()
            if rp:
                partners.add(rp)
            imsi = (doc.get("imsi") or "").strip()
            if imsi:
                imsis.add(imsi)
            iccid = (doc.get("iccid") or "").strip()
            if iccid:
                iccids.add(iccid)
            sv = (doc.get("sim_version") or "").strip() or "(unknown sim_version)"
            sim_versions[sv] += 1
            st = (doc.get("service_type") or "").strip() or "(unknown service_type)"
            service_types[st] += 1
            ss = (doc.get("sim_status") or "").strip() or "(unknown sim_status)"
            sim_status[ss] += 1
        return {
            "count": n,
            "capped": capped,
            "result_detail": result_counts,
            "procedures": procedures,
            "customers": sorted(customers)[:12],
            "roaming_partners": sorted(partners)[:12],
            "unique_imsi": len(imsis),
            "unique_iccid": len(iccids),
            "sim_versions": dict(sim_versions.most_common(10)),
            "service_types": dict(service_types.most_common(8)),
            "sim_status": dict(sim_status.most_common(6)),
        }

    cur = window_stats(window_start, window_end)
    prev = window_stats(prev_start, prev_end)

    narrative: List[str] = []
    if not hits:
        narrative.append(
            "**OpenSearch export** (`data/data.json`) was not found or is empty — Nexora cannot slice traffic from the snapshot."
        )
    else:
        narrative.append(
            f"**Time window** (alert-centred): **{window_start.strftime('%Y-%m-%d %H:%M')}** → "
            f"**{window_end.strftime('%Y-%m-%d %H:%M')}** UTC (±1h)."
        )
        narrative.append(
            f"**VPLMN / network filter:** `{vplmn_needle or '— (any VPLMN)'}`. "
            f"**Sponsor / roaming partner:** `{sponsor_needle or 'any'}`. "
            f"**MCC filter:** `{mcc_prefix or 'any'}`."
        )
        if focus_lost:
            narrative.append("You mentioned **lost service** — Nexora filtered to `result_detail == lost-service`.")
        if focus_lu:
            narrative.append(
                "You mentioned **location / mobility** — Nexora filtered to procedures **ULR, AIR, TAU, ULA**."
            )
        if cur.get("capped"):
            narrative.append(
                f"_(OpenSearch scan capped at **{MAX_OPENSEARCH_EVENTS}** events in-window for speed — counts are a lower bound.)_"
            )
        narrative.append(
            f"**Events in window:** **{cur['count']}** (vs **{prev['count']}** same clock window yesterday). "
            f"**Distinct subscribers (IMSI):** **{cur.get('unique_imsi', 0)}**. "
            f"**Distinct SIMs (ICCID):** **{cur.get('unique_iccid', 0)}**."
        )
        if cur.get("sim_versions"):
            sv_s = ", ".join(f"{k}: {v}" for k, v in list(cur["sim_versions"].items())[:6])
            narrative.append("**SIM profile versions in slice:** " + sv_s)
        if cur.get("service_types"):
            st_s = ", ".join(f"{k}: {v}" for k, v in list(cur["service_types"].items())[:5])
            narrative.append("**Service types (plan / product class):** " + st_s)
        if cur.get("sim_status"):
            ss_s = ", ".join(f"{k}: {v}" for k, v in list(cur["sim_status"].items())[:5])
            narrative.append("**SIM lifecycle status:** " + ss_s)
        if cur["result_detail"]:
            top_rd = sorted(cur["result_detail"].items(), key=lambda x: -x[1])[:5]
            narrative.append(
                "**Diameter / procedure result mix:** " + ", ".join(f"{k}: {v}" for k, v in top_rd)
            )
        if cur["customers"]:
            narrative.append("**Sample enterprise names:** " + ", ".join(cur["customers"][:8]))
        if cur["roaming_partners"]:
            narrative.append("**Roaming partners in the slice:** " + ", ".join(cur["roaming_partners"][:8]))

    return {
        "window_utc": {
            "start": window_start.isoformat(sep=" "),
            "end": window_end.isoformat(sep=" "),
        },
        "current": cur,
        "previous_day": prev,
        "narrative": "\n\n".join(narrative),
    }

def run_validation_checks(
    tiny_id: str,
    vplmn: str,
    symptoms: str,
    networks: List[str],
    coverage_matches: int,
    coverage_file_ok: bool,
    alert: Optional[dict] = None,
) -> List[Dict[str, str]]:
    """
    Validation checks — now includes a real lost-service count from data.json
    using the alert's createdAt_readable as the time anchor (±1 hour).
    """

    # ── Lost-service count ──────────────────────────────────────────────────
    lost_current = 0
    lost_previous = 0
    lost_customers: set = set()
    lost_partners: set = set()
    lost_sim_versions: set = set()
    lost_service_types: set = set()
    lost_window_note = ""
    lost_status = "pending"
    lost_detail = "No tinyId supplied — cannot anchor time window."

    if alert:
        center = parse_alert_center_time(alert)
        if center:
            window_start  = center - timedelta(hours=1)
            window_end    = center + timedelta(hours=1)
            prev_start    = window_start - timedelta(days=1)
            prev_end      = window_end   - timedelta(days=1)

            vplmn_needle = vplmn.strip() if vplmn else ""
            hits = get_cached_hits()

            def count_lost(start: datetime, end: datetime):
                n = 0
                custs:  set = set()
                parts:  set = set()
                simvs:  set = set()
                svcts:  set = set()
                for item in hits:
                    doc = item.get("_source", {}).get("doc", {})
                    doc_vplmn = doc.get("vplmn", "").strip()
                    if vplmn_needle and doc_vplmn != vplmn_needle:
                        continue
                    if doc.get("result_detail", "").strip().lower() != "lost-service":
                        continue
                    ts = parse_doc_timestamp(doc)
                    if ts is None or not (start <= ts <= end):
                        continue
                    n += 1
                    c = doc.get("customer_name", "").strip()
                    p = doc.get("roaming_partner", "").strip()
                    sv = doc.get("sim_version", "").strip()
                    st = doc.get("service_type", "").strip()
                    if c:  custs.add(c)
                    if p:  parts.add(p)
                    if sv: simvs.add(sv)
                    if st: svcts.add(st)
                return n, custs, parts, simvs, svcts

            lost_current,  lost_customers,   lost_partners, \
            lost_sim_versions, lost_service_types = count_lost(window_start, window_end)

            lost_previous, *_ = count_lost(prev_start, prev_end)

            lost_window_note = (
                f"{window_start.strftime('%Y-%m-%d %H:%M')} → "
                f"{window_end.strftime('%Y-%m-%d %H:%M')} UTC"
            )

            if lost_current == 0 and lost_previous == 0:
                lost_status = "ok"
                lost_detail = (
                    f"No `lost-service` events for VPLMN `{vplmn_needle or 'any'}` "
                    f"in window ({lost_window_note}). Previous day also 0."
                )
            elif lost_current > lost_previous * 1.5 + 1:
                lost_status = "warn"
                lost_detail = (
                    f"**{lost_current}** lost-service events in window ({lost_window_note}), "
                    f"vs **{lost_previous}** same window yesterday — spike detected. "
                    f"Customers: {', '.join(sorted(lost_customers)[:6]) or 'none'}. "
                    f"Partners: {', '.join(sorted(lost_partners)[:6]) or 'none'}. "
                    f"SIM versions: {', '.join(sorted(lost_sim_versions)[:6]) or 'none'}. "
                    f"Service types: {', '.join(sorted(lost_service_types)[:6]) or 'none'}."
                )
            else:
                lost_status = "ok"
                lost_detail = (
                    f"**{lost_current}** lost-service events in window ({lost_window_note}), "
                    f"vs **{lost_previous}** yesterday — within normal range. "
                    f"Customers: {', '.join(sorted(lost_customers)[:6]) or 'none'}."
                )
        else:
            lost_status = "warn"
            lost_detail = f"Alert found for tinyId `{tiny_id}` but timestamp could not be parsed."
    elif tiny_id:
        lost_status = "warn"
        lost_detail = f"tinyId `{tiny_id}` not found in `alerts.json` — cannot anchor time window."

    # ── Coverage check ───────────────────────────────────────────────────────
    cov_status = "ok" if coverage_matches else ("warn" if coverage_file_ok else "warn")

    checks = [
        {
            "id": "lost_service_count",
            "label": "Nexora — lost-service events (alert time window ±1 h)",
            "status": lost_status,
            "detail": lost_detail,
        },
        {
            "id": "alert_opensearch",
            "label": "Nexora — alert time ↔ OpenSearch export",
            "status": "ok",
            "detail": "Sliced `data/data.json` around the alert centre (±1h) with your filters.",
        },
        {
            "id": "coverage_file",
            "label": "Nexora — roaming coverage workbook (`coverage data.json`)",
            "status": cov_status,
            "detail": (
                f"Matched **{coverage_matches}** coverage row(s) for country / network / sponsor. "
                "Nexora uses this for failover networks and sponsor options."
            ),
        },
        {
            "id": "coverage_rat",
            "label": "Nexora — site-token RAT hints",
            "status": "ok" if networks else "warn",
            "detail": (
                f"Tokens: {', '.join(networks) or 'none — rely on VPLMN / coverage sheet'}."
            ),
        },
        {
            "id": "jira_similarity",
            "label": "Nexora — Jira similarity",
            "status": "ok",
            "detail": "Semantic search over indexed Jira tickets for comparable fixes.",
        },
    ]
    return checks


def _format_similar_results(raw: Any, limit: int = 5) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not raw:
        return out
    rows = raw if isinstance(raw, list) else []
    for r in rows[:limit]:
        if not isinstance(r, dict):
            continue
        desc = (r.get("description") or "")[:420]
        out.append(
            {
                "issue_key": r.get("issue_key") or r.get("key") or "—",
                "summary": (r.get("summary") or "")[:280],
                "status": r.get("status") or "",
                "match_score": r.get("combined_score")
                or r.get("match_score")
                or r.get("similarity_score")
                or "",
                "resolution_snippet": desc,
            }
        )
    return out


def rag_search(query: str, top_k: int = 6) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        from similarity_search.routes import rag_engine
    except Exception as e:
        return [], str(e)

    if not rag_engine:
        return [], "Similarity engine not initialized"

    try:
        data = rag_engine.search_similar_tickets_advanced(
            query=query,
            top_k=top_k,
            search_type="semantic",
            status_filter=None,
            date_weight=0.35,
            similarity_weight=0.65,
            max_days_back=540,
        )
        results = data.get("results") or []
        return _format_similar_results(results), None
    except Exception as e:
        return [], str(e)


def build_rag_query(
    symptoms: str,
    vplmn: str,
    sponsor: str,
    country: str,
    networks: List[str],
) -> str:
    parts = [
        (symptoms or "").strip(),
        f"VPLMN / network: {vplmn or 'n/a'}",
        f"Roaming sponsor: {sponsor or 'n/a'}",
        f"Country: {country or 'n/a'}",
    ]
    if networks:
        parts.append("Site tokens: " + ", ".join(networks))
    parts.append("GNOC telecom incident root cause resolution playbook")
    return "\n".join(p for p in parts if p)


def resolution_from_similar(incidents: List[Dict[str, Any]]) -> str:
    if not incidents:
        return "**Nexora:** I did not find close Jira neighbours — take a PCAP on the failing attach / ULR leg and compare with hub blocking in coverage."
    lines = []
    for inc in incidents[:3]:
        key = inc.get("issue_key", "—")
        summ = inc.get("summary", "")
        snip = inc.get("resolution_snippet") or ""
        lines.append(f"- **{key}** ({summ[:120]}): _Past context:_ {snip[:220]}…" if len(snip) > 220 else f"- **{key}** ({summ[:120]}): _Past context:_ {snip}")
    return "**Nexora — how similar tickets were solved (Jira):**\n" + "\n".join(lines)


def build_nexora_action_plan(
    os_report: Dict[str, Any],
    cov_report: Dict[str, Any],
    similar: List[Dict[str, Any]],
) -> str:
    lines: List[str] = ["**Nexora — suggested next steps:**"]
    cur = (os_report or {}).get("current") or {}
    if cur.get("count", 0) > 0:
        lines.append(
            "- Quantify customer impact using the IMSI / ICCID counts above; open a bridge if `lost-service` dominates the slice."
        )
    else:
        lines.append(
            "- Traffic slice is thin in the export window — widen time or confirm VPLMN spelling against the coverage sheet, then capture PCAP."
        )
    if cov_report.get("alternate_networks"):
        lines.append(
            "- If the visited network path is impaired, test automatic steering against an **alternate PLMN** listed in coverage (`Available: Yes`)."
        )
    if cov_report.get("alternate_sponsors"):
        lines.append(
            "- If sponsor RS / diameter errors repeat, try a **different roaming sponsor** from the available list for that country."
        )
    if similar:
        lines.append(
            f"- Re-use the playbook from **{similar[0].get('issue_key', 'top Jira match')}** — description snippets above often list the exact config change."
        )
    lines.append("- Optional: run **PCAP Analyzer** if you need signalling proof for Jira / partner comms.")
    return "\n".join(lines)


def generate_templates(
    symptoms: str,
    vplmn: str,
    sponsor: str,
    country: str,
    tiny_id: str,
    incidents: List[Dict[str, Any]],
    opensearch_narrative: str,
    coverage_narrative: str,
) -> Dict[str, str]:
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    top = incidents[0] if incidents else {}
    key = top.get("issue_key", "NEXORA-DRAFT")
    net_label = vplmn or (incidents[0].get("summary", "")[:40] if incidents else "Network TBD")
    jsm = f"""Title: [GNOC][{net_label}] {symptoms[:80] or 'Service observation'} — Nexora draft ({ts})

**Summary**
{symptoms[:500]}

**Identifiers**
- Ops alert **tinyId:** {tiny_id or 'manual / none'}
- **VPLMN / network:** {vplmn or 'TBD'}
- **Sponsor / roaming partner:** {sponsor or 'TBD'}
- **Country:** {country or 'TBD'}

**Nexora — OpenSearch export slice**
{opensearch_narrative[:700]}

**Nexora — Coverage workbook correlation**
{coverage_narrative[:700]}

**Similar Jira tickets**
- Pattern reference: **{key}** — mirror the resolution notes from that ticket where applicable.

**Impact**
- Services: data / SMS / voice / location update (confirm from slice)
- Devices: IMSI / ICCID counts, SIM versions, and service types are listed in Nexora’s OpenSearch summary.

**Checklist**
- [ ] PCAP attached if partner escalation needs signalling proof
- [ ] Status page updated if subscribers are impacted
- [ ] Maintenance / steering rules checked against coverage alternates

**Next steps**
1. Execute Nexora’s failover / sponsor suggestions where safe in lab or controlled rollout
2. Route to owning team with this draft
"""
    status_page = f"""Status page draft — Nexora generated ({ts})

**Status**: Investigating  
**Scope**: {country or 'Region TBD'} — **{net_label}** ({sponsor or 'sponsor TBD'})

**Nexora summary**: I correlated the exported OpenSearch window with your alert time, validated roaming rows in `coverage data.json`, and matched historical Jira incidents (**{key}**). Distinct subscriber and SIM counts, SIM versions, and service types are in the internal Nexora panel.

**Customer-facing line**: We are investigating reports that may affect roaming connectivity. We will post the next update within 30 minutes or sooner if the root cause is confirmed.

**Reference**: Alert tinyId `{tiny_id or 'n/a'}`.

_Have Comms review before anything external goes live._
"""
    return {"jsm": jsm.strip(), "status_page": status_page.strip()}


def _yes_no(text: str) -> Optional[bool]:
    t = (text or "").strip().lower()
    if t in ("yes", "y", "yeah", "yep", "please", "sure", "ok", "upload", "pcap"):
        return True
    if t in ("no", "n", "nope", "skip", "not now", "continue"):
        return False
    return None

def build_lost_service_narrative(
    tiny_id: str,
    vplmn: str,
    alert: Optional[dict],
) -> str:
    """
    Returns a formatted lost-service analysis block for the main chat message.
    Mirrors the reference script output exactly.
    """
    if not alert:
        if tiny_id:
            return f"_(tinyId `{tiny_id}` not found in `alerts.json` — cannot anchor lost-service window.)_"
        return ""

    center = parse_alert_center_time(alert)
    if not center:
        return f"_(Alert found for tinyId `{tiny_id}` but timestamp could not be parsed.)_"

    window_start = center - timedelta(hours=1)
    window_end   = center + timedelta(hours=1)
    prev_start   = window_start - timedelta(days=1)
    prev_end     = window_end   - timedelta(days=1)

    vplmn_needle = (vplmn or "").strip()
    hits = get_cached_hits()

    def analyze(start: datetime, end: datetime):
        count = 0
        customers:     set = set()
        partners:      set = set()
        sim_versions:  set = set()
        service_types: set = set()
        for item in hits:
            doc = item.get("_source", {}).get("doc", {})
            if vplmn_needle and doc.get("vplmn", "").strip() != vplmn_needle:
                continue
            if doc.get("result_detail", "").strip().lower() != "lost-service":
                continue
            ts = parse_doc_timestamp(doc)
            if ts is None or not (start <= ts <= end):
                continue
            count += 1
            c  = doc.get("customer_name",    "").strip()
            p  = doc.get("roaming_partner",  "").strip()
            sv = doc.get("sim_version",      "").strip()
            st = doc.get("service_type",     "").strip()
            if c:  customers.add(c)
            if p:  partners.add(p)
            if sv: sim_versions.add(sv)
            if st: service_types.add(st)
        return count, customers, partners, sim_versions, service_types

    cur_count, cur_custs, cur_parts, cur_simvs, cur_svcts = analyze(window_start, window_end)
    prev_count, *_ = analyze(prev_start, prev_end)

    alert_msg = alert.get("message", "")
    lines = [
        "**Nexora — Lost-Service Analysis (alert time window ±1 h)**",
        "",
        f"**Alert message:** {alert_msg[:180]}{'…' if len(alert_msg) > 180 else ''}",
        f"**Extracted VPLMN:** `{vplmn_needle or '(not found)'}`",
        f"**Time window (current):** {window_start.strftime('%Y-%m-%d %H:%M')} → {window_end.strftime('%Y-%m-%d %H:%M')} UTC",
        f"**Time window (previous day):** {prev_start.strftime('%Y-%m-%d %H:%M')} → {prev_end.strftime('%Y-%m-%d %H:%M')} UTC",
        "",
        "**--- RESULTS ---**",
        f"**VPLMN:** {vplmn_needle or '(any)'}",
        "",
        "**--- CURRENT WINDOW ---**",
        f"**Count:** {cur_count}",
        "",
        f"**Unique Customers ({len(cur_custs)}):**",
        (", ".join(sorted(cur_custs)) if cur_custs else "_None_"),
        "",
        f"**Roaming Partners ({len(cur_parts)}):**",
        (", ".join(sorted(cur_parts)) if cur_parts else "_None_"),
        "",
        f"**SIM Versions ({len(cur_simvs)}):**",
        (", ".join(sorted(cur_simvs)) if cur_simvs else "_None_"),
        "",
        f"**Service Types ({len(cur_svcts)}):**",
        (", ".join(sorted(cur_svcts)) if cur_svcts else "_None_"),
        "",
        "**--- PREVIOUS DAY WINDOW ---**",
        f"**Count:** {prev_count}",
    ]

    # Spike callout
    if cur_count > 0 and prev_count == 0:
        lines.append("")
        lines.append(f"⚠️ **Spike detected:** {cur_count} lost-service events today vs 0 yesterday.")
    elif cur_count > prev_count * 1.5 + 1:
        pct = int((cur_count - prev_count) / max(prev_count, 1) * 100)
        lines.append("")
        lines.append(f"⚠️ **Spike detected:** {cur_count} today vs {prev_count} yesterday (+{pct}% increase).")
    elif cur_count == 0:
        lines.append("")
        lines.append("✅ **No lost-service events** in this window for the given VPLMN.")

    return "\n".join(lines)

@nexora_bp.route("/")
def nexora_home():
    return render_template("nexora.html")


@nexora_bp.route("/interact", methods=["POST"])
def interact():
    """
    Phases:
      collect_context      — any of tiny_id, country, vplmn, sponsor, symptoms
      await_ticket_confirm — show lost-service results, ask yes/no to create JSM ticket
      await_pcap_choice    — PCAP yes/no after ticket decision
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}

    phase        = (data.get("phase") or "collect_context").strip()
    pcap_choice  = data.get("pcap_choice")
    user_message = (data.get("user_message") or "").strip()

    # ── Restore session state sent back from the browser ─────────────────────
    last_tiny          = (data.get("last_tiny_id")              or "").strip()
    last_country       = (data.get("last_country")              or "").strip()
    last_vplmn         = (data.get("last_vplmn")                or "").strip()
    last_sponsor       = (data.get("last_sponsor")              or "").strip()
    last_symptoms      = (data.get("last_symptoms")             or "").strip()
    last_alert_msg     = (data.get("last_alert_message")        or "").strip()
    last_center_iso    = (data.get("last_center_time_iso")      or "").strip()
    last_networks      = data.get("last_networks") or []
    if not isinstance(last_networks, list):
        last_networks  = []
    last_os_narrative  = (data.get("last_opensearch_narrative") or "").strip()
    last_cov_narrative = (data.get("last_coverage_narrative")   or "").strip()
    last_lost_block    = (data.get("last_lost_block")           or "").strip()
    last_jsm_summary   = (data.get("last_jsm_summary")         or "").strip()
    last_jsm_desc      = (data.get("last_jsm_description")     or "").strip()

    def session_payload(
        networks: List[str],
        os_narrative: str  = "",
        cov_narrative: str = "",
        lost_block: str    = "",
        jsm_summary: str   = "",
        jsm_desc: str      = "",
    ) -> Dict[str, Any]:
        return {
            "last_tiny_id":             last_tiny,
            "last_country":             last_country,
            "last_vplmn":               last_vplmn,
            "last_sponsor":             last_sponsor,
            "last_symptoms":            last_symptoms,
            "last_alert_message":       last_alert_msg,
            "last_center_time_iso":     last_center_iso,
            "last_networks":            networks,
            "last_opensearch_narrative": os_narrative  or last_os_narrative,
            "last_coverage_narrative":  cov_narrative  or last_cov_narrative,
            "last_lost_block":          lost_block     or last_lost_block,
            "last_jsm_summary":         jsm_summary    or last_jsm_summary,
            "last_jsm_description":     jsm_desc       or last_jsm_desc,
        }

    # =========================================================================
    # PHASE: await_pcap_choice
    # =========================================================================
    if phase == "await_pcap_choice":
        choice: Optional[bool] = None
        if pcap_choice is True or pcap_choice is False:
            choice = bool(pcap_choice)
        elif user_message:
            choice = _yes_no(user_message)
        if choice is None:
            return jsonify({
                "success": False,
                "error": "Say **yes** or **no** to PCAP analysis (or use the buttons).",
            }), 400

        if choice:
            msg = (
                "**Nexora:** Redirecting you to PCAP Analyzer — upload your trace there and "
                "attach the export to the Jira ticket already created.\n\n"
                "__REDIRECT__:http://127.0.0.1:5000/pcap_analysis/"
            )
        else:
            msg = (
                "**Nexora:** Understood — skipping PCAP for now. "
                "The **JSM** and **status page** drafts in the tabs are ready to copy."
            )

        nets = last_networks or extract_network_names(last_vplmn + " " + last_symptoms)
        return jsonify({
            "success":           True,
            "phase":             "done",
            "assistant_message": msg,
            "validation_checks": [],
            "coverage":          coverage_context_for_network(nets),
            "coverage_file":     {},
            "similar_incidents": [],
            "rag_error":         None,
            "templates":         {},
            "opensearch_report": {"narrative": last_os_narrative},
            **session_payload(nets),
        })

    # =========================================================================
    # PHASE: await_ticket_confirm  — user replied yes/no to creating the ticket
    # =========================================================================
    if phase == "await_ticket_confirm":
        ticket_choice = data.get("ticket_choice")
        choice_bool: Optional[bool] = None
        if ticket_choice is True or ticket_choice is False:
            choice_bool = bool(ticket_choice)
        elif user_message:
            choice_bool = _yes_no(user_message)

        if choice_bool is None:
            return jsonify({
                "success": False,
                "error":   "Please choose **Yes — create ticket** or **No — skip**.",
            }), 400

        nets = last_networks or []

        if choice_bool:
            # Create the JSM ticket now
            status_code, response_text = create_jsm_ticket(last_jsm_summary, last_jsm_desc)
            print("JSM Ticket Created:", status_code, response_text)

            if status_code in (200, 201):
                ticket_msg = (
                    "✅ **JSM ticket created successfully.**\n\n"
                    f"**Summary:** {last_jsm_summary}\n\n"
                    "The full lost-service analysis has been added to the ticket description."
                )
            else:
                ticket_msg = (
                    f"⚠️ **JSM ticket creation returned status {status_code}.** "
                    "Check the server logs — the draft is still in the JSM tab.\n\n"
                    f"Response: {response_text[:300]}"
                )
        else:
            ticket_msg = (
                "**Nexora:** Ticket creation skipped. "
                "The draft is still available in the **JSM ticket** tab if you change your mind."
            )

        ticket_msg += (
            "\n\n---\n\n"
            "**Do you want to run PCAP analysis?** "
            "Upload a trace for deeper signalling proof."
        )

        return jsonify({
            "success":           True,
            "phase":             "await_pcap_choice",
            "assistant_message": ticket_msg,
            "validation_checks": [],
            "coverage":          coverage_context_for_network(nets),
            "coverage_file":     {},
            "similar_incidents": [],
            "rag_error":         None,
            "templates":         {},
            "opensearch_report": {"narrative": last_os_narrative},
            **session_payload(nets),
        })

    # =========================================================================
    # PHASE: collect_context  — main analysis pass
    # =========================================================================
    if phase != "collect_context":
        return jsonify({"success": False, "error": f"Unknown phase: {phase}"}), 400

    tiny_id  = (data.get("tiny_id")        or "").strip() or last_tiny
    country  = (data.get("country")        or "").strip() or last_country
    vplmn    = (data.get("vplmn") or data.get("network_name") or "").strip() or last_vplmn
    sponsor  = (data.get("sponsor")        or "").strip() or last_sponsor
    symptoms = (data.get("symptoms") or user_message or "").strip() or last_symptoms

    any_ctx = any(x.strip() for x in (tiny_id, country, vplmn, sponsor, symptoms) if x)
    if not any_ctx:
        return jsonify({
            "success": False,
            "error":   "Fill **at least one** field (tinyId, country, network, sponsor, or symptoms).",
        }), 400

    if not symptoms.strip():
        symptoms = "Automated GNOC context check from the supplied tinyId / country / network / sponsor fields."

    # ── Alert lookup ──────────────────────────────────────────────────────────
    alert         = find_alert_by_tiny_id(tiny_id) if tiny_id else None
    alert_msg     = ""
    tiny_not_found_note = ""
    center: datetime

    if alert:
        center    = parse_alert_center_time(alert) or datetime.utcnow()
        alert_msg = alert.get("message") or ""
        inferred  = extract_vplmn_from_alert_message(alert_msg)
        if not vplmn and inferred:
            vplmn = inferred
    else:
        center = datetime.utcnow()
        if data.get("incident_time"):
            try:
                center = datetime.fromisoformat(
                    str(data["incident_time"])[:19].replace("Z", "")
                )
            except Exception:
                pass
        if tiny_id:
            tiny_not_found_note = (
                f"\n\n_(Nexora note: tinyId **{tiny_id}** not in `alerts.json` — "
                f"centred on **{center.strftime('%Y-%m-%d %H:%M')}** UTC.)_"
            )

    tok = extract_network_names(symptoms)
    if not vplmn and tok:
        vplmn = tok[0]

    # ── Lost-service block ────────────────────────────────────────────────────
    def build_lost_service_block() -> str:
        if not alert:
            if tiny_id:
                return f"_(tinyId `{tiny_id}` not found in `alerts.json` — cannot anchor lost-service window.)_"
            return ""

        ts_center = parse_alert_center_time(alert)
        if not ts_center:
            return f"_(Alert found for tinyId `{tiny_id}` but timestamp could not be parsed.)_"

        w_start = ts_center - timedelta(hours=1)
        w_end   = ts_center + timedelta(hours=1)
        p_start = w_start   - timedelta(days=1)
        p_end   = w_end     - timedelta(days=1)

        needle = vplmn.strip()
        hits   = get_cached_hits()

        def analyze(start: datetime, end: datetime):
            count         = 0
            customers:     set = set()
            partners:      set = set()
            sim_versions:  set = set()
            service_types: set = set()
            for item in hits:
                doc = item.get("_source", {}).get("doc", {})
                if needle and doc.get("vplmn", "").strip() != needle:
                    continue
                if doc.get("result_detail", "").strip().lower() != "lost-service":
                    continue
                ts = parse_doc_timestamp(doc)
                if ts is None or not (start <= ts <= end):
                    continue
                count += 1
                c  = doc.get("customer_name",  "").strip()
                p  = doc.get("roaming_partner", "").strip()
                sv = doc.get("sim_version",     "").strip()
                st = doc.get("service_type",    "").strip()
                if c:  customers.add(c)
                if p:  partners.add(p)
                if sv: sim_versions.add(sv)
                if st: service_types.add(st)
            return count, customers, partners, sim_versions, service_types

        cur_count,  cur_custs, cur_parts, cur_simvs, cur_svcts = analyze(w_start, w_end)
        prev_count, *_                                          = analyze(p_start, p_end)

        a_msg = alert.get("message", "")
        lines = [
            "**Nexora — Lost-Service Analysis (alert time window ±1 h)**",
            "",
            f"**Alert message:** {a_msg[:180]}{'…' if len(a_msg) > 180 else ''}",
            f"**Extracted VPLMN:** `{needle or '(not found)'}`",
            f"**Time window (current):** {w_start.strftime('%Y-%m-%d %H:%M')} → {w_end.strftime('%Y-%m-%d %H:%M')} UTC",
            f"**Time window (prev day):** {p_start.strftime('%Y-%m-%d %H:%M')} → {p_end.strftime('%Y-%m-%d %H:%M')} UTC",
            "",
            "**--- RESULTS ---**",
            f"**VPLMN:** {needle or '(any)'}",
            "",
            "**--- CURRENT WINDOW ---**",
            f"**Count:** {cur_count}",
            "",
            f"**Unique Customers ({len(cur_custs)}):**",
            (", ".join(sorted(cur_custs)) if cur_custs else "_None_"),
            "",
            f"**Roaming Partners ({len(cur_parts)}):**",
            (", ".join(sorted(cur_parts)) if cur_parts else "_None_"),
            "",
            f"**SIM Versions ({len(cur_simvs)}):**",
            (", ".join(sorted(cur_simvs)) if cur_simvs else "_None_"),
            "",
            f"**Service Types ({len(cur_svcts)}):**",
            (", ".join(sorted(cur_svcts)) if cur_svcts else "_None_"),
            "",
            "**--- PREVIOUS DAY WINDOW ---**",
            f"**Count:** {prev_count}",
        ]

        if cur_count > 0 and prev_count == 0:
            lines += ["", f"⚠️ **Spike detected:** {cur_count} lost-service events today vs 0 yesterday."]
        elif cur_count > prev_count * 1.5 + 1:
            pct = int((cur_count - prev_count) / max(prev_count, 1) * 100)
            lines += ["", f"⚠️ **Spike detected:** {cur_count} today vs {prev_count} yesterday (+{pct}% increase)."]
        elif cur_count == 0:
            lines += ["", "✅ **No lost-service events** in this window for the given VPLMN."]

        return "\n".join(lines)

    lost_service_block = build_lost_service_block()

    # ── Coverage (no OpenSearch traffic slice) ────────────────────────────────
    mcc_prefix    = country_to_mcc_prefix(country)
    cov_report    = build_coverage_file_report(country, vplmn, sponsor, symptoms)
    cov_narrative = cov_report.get("narrative", "")

    # Keep opensearch_report for internal use (validation checks / templates)
    # but do NOT include its narrative in the chat message
    opensearch_report = analyze_opensearch_correlation(
        center, vplmn, sponsor, mcc_prefix, symptoms
    )
    os_narrative = opensearch_report.get("narrative", "")

    networks = extract_network_names(f"{vplmn} {symptoms}")
    if vplmn.strip():
        head     = vplmn.strip()
        networks = [head] + [n for n in networks if _norm_txt(n) != _norm_txt(head)]

    # ── Validation checks ─────────────────────────────────────────────────────
    validation_checks = run_validation_checks(
        tiny_id=tiny_id,
        vplmn=vplmn,
        symptoms=symptoms,
        networks=networks,
        coverage_matches=int(cov_report.get("matches") or 0),
        coverage_file_ok=bool(cov_report.get("source_found")),
        alert=alert,
    )

    coverage = coverage_context_for_network(networks)
    coverage["file_insight"] = {
        "matches":              cov_report.get("matches", 0),
        "alternate_networks":   cov_report.get("alternate_networks", [])[:14],
        "alternate_sponsors":   cov_report.get("alternate_sponsors", [])[:16],
        "product_versions_top": cov_report.get("product_versions_top", [])[:8],
    }

    # ── RAG / Jira ────────────────────────────────────────────────────────────
    pq = build_rag_query(symptoms, vplmn, sponsor, country, networks)
    similar_incidents, rag_error = rag_search(pq)
    res_hint    = resolution_from_similar(similar_incidents)
    action_plan = build_nexora_action_plan(opensearch_report, cov_report, similar_incidents)

    # ── Templates ─────────────────────────────────────────────────────────────
    templates = generate_templates(
        symptoms, vplmn, sponsor, country, tiny_id,
        similar_incidents, os_narrative, cov_narrative,
    )

    # ── Pre-build JSM ticket content (sent to browser; created only on confirm) ─
    jsm_summary = f"[GNOC] {alert_msg[:120] if alert_msg else (vplmn or 'Network') + ' - ' + symptoms[:60]}"
    jsm_description = f"""{lost_service_block}

--- Coverage ---
{cov_narrative[:800]}

--- Similar Jira Tickets ---
{res_hint[:600]}

--- Action Plan ---
{action_plan[:600]}

TinyId: {tiny_id}
Country: {country}
Network / VPLMN: {vplmn}
Sponsor: {sponsor}
""".strip()

    # ── Update session ────────────────────────────────────────────────────────
    last_tiny          = tiny_id
    last_country       = country
    last_vplmn         = vplmn
    last_sponsor       = sponsor
    last_symptoms      = symptoms
    last_alert_msg     = alert_msg
    last_center_iso    = center.isoformat(sep=" ")
    last_networks      = networks
    last_os_narrative  = os_narrative
    last_cov_narrative = cov_narrative

    # ── Assemble reply ────────────────────────────────────────────────────────
    reply_lines: List[str] = []

    # 1. Lost-service analysis
    if lost_service_block:
        reply_lines.append(lost_service_block)
        reply_lines.append("")

    # 2. Coverage workbook
    reply_lines.append("**Nexora — roaming coverage workbook**")
    reply_lines.append(cov_narrative)

    # 3. Alert not-found note
    if tiny_not_found_note:
        reply_lines.append(tiny_not_found_note)

    # 4. Jira hints + action plan
    reply_lines.append("")
    reply_lines.append(res_hint)
    reply_lines.append("")
    reply_lines.append(action_plan)

    if rag_error:
        reply_lines.append(f"\n_(Jira engine note: {rag_error})_")

    # 5. Ticket confirmation prompt
    reply_lines.append(
        "\n\n---\n\n"
        "**Nexora:** Based on the lost-service analysis above, do you want to "
        "**create a JSM ticket** now with this information?"
    )

    return jsonify({
        "success":           True,
        "phase":             "await_ticket_confirm",
        "assistant_message": "\n\n".join(reply_lines),
        "validation_checks": validation_checks,
        "coverage":          coverage,
        "coverage_file":     cov_report,
        "similar_incidents": similar_incidents,
        "rag_error":         rag_error,
        "templates":         templates,
        "opensearch_report": opensearch_report,
        **session_payload(
            networks,
            os_narrative,
            cov_narrative,
            lost_block  = lost_service_block,
            jsm_summary = jsm_summary,
            jsm_desc    = jsm_description,
        ),
    })
@nexora_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"service": "nexora", "ok": True})
