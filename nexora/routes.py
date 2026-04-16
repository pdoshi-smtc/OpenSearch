"""
Nexora — GNOC Advance Assistant: quick checks, OpenSearch correlation, Jira similarity,
PCAP handoff, status page and Jira templates.
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
    user_text: str,
    networks: List[str],
    coverage_matches: int,
    coverage_file_ok: bool,
) -> List[Dict[str, str]]:
    cov_status = "ok" if coverage_matches else ("warn" if coverage_file_ok else "warn")
    checks = [
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


@nexora_bp.route("/")
def nexora_home():
    return render_template("nexora.html")


@nexora_bp.route("/interact", methods=["POST"])
def interact():
    """
    Phases:
      collect_context — any of tiny_id, country, vplmn, sponsor, symptoms (≥1 required)
      await_pcap_choice — PCAP yes/no (templates already returned from collect_context)
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}

    phase = (data.get("phase") or "collect_context").strip()
    pcap_choice = data.get("pcap_choice")
    user_message = (data.get("user_message") or "").strip()

    reply_lines: List[str] = []
    templates: Dict[str, str] = {}
    similar_incidents: List[Dict[str, Any]] = []
    rag_error: Optional[str] = None
    opensearch_report: Dict[str, Any] = {}
    validation_checks: List[Dict[str, str]] = []

    last_tiny = (data.get("last_tiny_id") or "").strip()
    last_country = (data.get("last_country") or "").strip()
    last_vplmn = (data.get("last_vplmn") or "").strip()
    last_sponsor = (data.get("last_sponsor") or "").strip()
    last_symptoms = (data.get("last_symptoms") or "").strip()
    last_alert_msg = (data.get("last_alert_message") or "").strip()
    last_center_iso = (data.get("last_center_time_iso") or "").strip()
    last_networks = data.get("last_networks") or []
    if not isinstance(last_networks, list):
        last_networks = []
    last_os_narrative = (data.get("last_opensearch_narrative") or "").strip()
    last_cov_narrative = (data.get("last_coverage_narrative") or "").strip()

    def session_payload(
        networks: List[str],
        os_narrative: str = "",
        cov_narrative: str = "",
    ) -> Dict[str, Any]:
        return {
            "last_tiny_id": last_tiny,
            "last_country": last_country,
            "last_vplmn": last_vplmn,
            "last_sponsor": last_sponsor,
            "last_symptoms": last_symptoms,
            "last_alert_message": last_alert_msg,
            "last_center_time_iso": last_center_iso,
            "last_networks": networks,
            "last_opensearch_narrative": os_narrative or last_os_narrative,
            "last_coverage_narrative": cov_narrative or last_cov_narrative,
        }

    # ----- PCAP follow-up (templates already generated) -----
    if phase == "await_pcap_choice":
        choice: Optional[bool] = None
        if pcap_choice is True or pcap_choice is False:
            choice = bool(pcap_choice)
        elif user_message:
            choice = _yes_no(user_message)
        if choice is None:
            return jsonify(
                {
                    "success": False,
                    "error": "Say **yes** or **no** to PCAP analysis (or use the buttons).",
                }
            ), 400

        if choice:
            msg = (
                "**Nexora:** Great — open **PCAP Analyzer** from the Next actions tab, upload your trace, "
                "and attach the export to the Jira draft I already prepared."
            )
        else:
            msg = (
                "**Nexora:** Understood — skipping PCAP for now. The **JSM** and **status page** drafts in the tabs "
                "are ready to copy; refine wording if you need a narrower customer message."
            )
        nets = last_networks or extract_network_names(last_vplmn + " " + last_symptoms)
        return jsonify(
            {
                "success": True,
                "phase": "done",
                "assistant_message": msg,
                "validation_checks": [],
                "coverage": coverage_context_for_network(nets),
                "coverage_file": {},
                "similar_incidents": [],
                "rag_error": None,
                "templates": {},
                "opensearch_report": {"narrative": last_os_narrative},
                **session_payload(nets),
            }
        )

    if phase != "collect_context":
        return jsonify({"success": False, "error": f"Unknown phase: {phase}"}), 400

    tiny_id = (data.get("tiny_id") or "").strip() or last_tiny
    country = (data.get("country") or "").strip() or last_country
    vplmn = (data.get("vplmn") or data.get("network_name") or "").strip() or last_vplmn
    sponsor = (data.get("sponsor") or "").strip() or last_sponsor
    symptoms = (data.get("symptoms") or user_message or "").strip() or last_symptoms

    any_ctx = any(x.strip() for x in (tiny_id, country, vplmn, sponsor, symptoms) if x)
    if not any_ctx:
        return jsonify(
            {
                "success": False,
                "error": "Fill **at least one** field (tinyId, country, network, sponsor, or what you are seeing), then run the check.",
            }
        ), 400

    if not symptoms.strip():
        symptoms = "Automated GNOC context check from the supplied tinyId / country / network / sponsor fields."

    alert = find_alert_by_tiny_id(tiny_id) if tiny_id else None
    center: datetime
    alert_msg = ""
    tiny_not_found_note = ""
    if alert:
        center = parse_alert_center_time(alert) or datetime.utcnow()
        alert_msg = alert.get("message") or ""
        inferred = extract_vplmn_from_alert_message(alert_msg)
        if not vplmn and inferred:
            vplmn = inferred
    else:
        center = datetime.utcnow()
        if data.get("incident_time"):
            try:
                raw = str(data.get("incident_time"))[:19]
                center = datetime.fromisoformat(raw.replace("Z", ""))
            except Exception:
                pass
        if tiny_id:
            tiny_not_found_note = (
                f"\n\n_(Nexora note: tinyId **{tiny_id}** is not in `data/alerts.json` — I centred the window on "
                f"**{center.strftime('%Y-%m-%d %H:%M')}** UTC. Add the alert export for an exact timestamp.)_"
            )

    tok = extract_network_names(symptoms)
    if not vplmn and tok:
        vplmn = tok[0]

    mcc_prefix = country_to_mcc_prefix(country)
    cov_report = build_coverage_file_report(country, vplmn, sponsor, symptoms)
    cov_narrative = cov_report.get("narrative", "")

    opensearch_report = analyze_opensearch_correlation(
        center, vplmn, sponsor, mcc_prefix, symptoms
    )
    os_narrative = opensearch_report.get("narrative", "")

    networks = extract_network_names(f"{vplmn} {symptoms}")
    if (vplmn or "").strip():
        head = (vplmn or "").strip()
        networks = [head] + [n for n in networks if _norm_txt(n) != _norm_txt(head)]

    validation_checks = run_validation_checks(
        symptoms,
        networks,
        int(cov_report.get("matches") or 0),
        bool(cov_report.get("source_found")),
    )
    coverage = coverage_context_for_network(networks)
    coverage["file_insight"] = {
        "matches": cov_report.get("matches", 0),
        "alternate_networks": cov_report.get("alternate_networks", [])[:14],
        "alternate_sponsors": cov_report.get("alternate_sponsors", [])[:16],
        "product_versions_top": cov_report.get("product_versions_top", [])[:8],
    }

    pq = build_rag_query(symptoms, vplmn, sponsor, country, networks)
    similar_incidents, rag_error = rag_search(pq)
    res_hint = resolution_from_similar(similar_incidents)
    action_plan = build_nexora_action_plan(opensearch_report, cov_report, similar_incidents)
    templates = generate_templates(
        symptoms,
        vplmn,
        sponsor,
        country,
        tiny_id,
        similar_incidents,
        os_narrative,
        cov_narrative,
    )

    
    # =========================
    # 🔥 FIXED ISSUE DETECTION
    # =========================

    issue_detected = False

    event_count = opensearch_report.get("current", {}).get("count", 0)

    # Condition 1: Lost service keyword
    if "lost" in symptoms.lower():
        issue_detected = True

    # Condition 2: Any alert-based issue (better for your case)
    if tiny_id:
        issue_detected = True

    # Condition 3: Node Down (VERY IMPORTANT for your data)
    if "down" in (alert_msg or "").lower():
        issue_detected = True

    # Condition 4: Event spike (keep optional)
    if event_count > 10:
        issue_detected = True


    # =========================
    # 🚀 CREATE TICKET
    # =========================

    print("DEBUG:")
    print("event_count:", event_count)
    print("tiny_id:", tiny_id)
    print("alert_msg:", alert_msg)
    print("issue_detected:", issue_detected)
    if issue_detected:
        summary = f"[GNOC] {vplmn or 'Network'} - {symptoms[:50]}"

        description = f"""
    Issue detected by Nexora

    TinyId: {tiny_id}
    Alert: {alert_msg}

    Symptoms: {symptoms}
    Country: {country}
    Network: {vplmn}
    Sponsor: {sponsor}

    --- OpenSearch ---
    {opensearch_report.get("narrative", "")[:500]}

    --- Coverage ---
    {cov_report.get("narrative", "")[:500]}
    """

        status_code, response_text = create_jsm_ticket(summary, description)

        print("JSM Ticket Created:", status_code)
        print(response_text)


    last_tiny = tiny_id
    last_country = country
    last_vplmn = vplmn
    last_sponsor = sponsor
    last_symptoms = symptoms
    last_alert_msg = alert_msg
    last_center_iso = center.isoformat(sep=" ")
    last_networks = networks
    last_os_narrative = os_narrative
    last_cov_narrative = cov_narrative

    reply_lines.append("**Nexora — traffic slice (OpenSearch export)**")
    reply_lines.append(opensearch_report.get("narrative", ""))
    reply_lines.append("")
    reply_lines.append("**Nexora — roaming coverage workbook**")
    reply_lines.append(cov_narrative)
    if tiny_not_found_note:
        reply_lines.append(tiny_not_found_note)
    if alert:
        reply_lines.append(
            f"\n**Linked alert (context):** {alert_msg[:400]}{'…' if len(alert_msg) > 400 else ''}"
        )
    reply_lines.append("")
    reply_lines.append(res_hint)
    reply_lines.append("")
    reply_lines.append(action_plan)
    if rag_error:
        reply_lines.append(f"\n_(Jira engine note: {rag_error})_")

    reply_lines.append(
        "\n\n**Nexora:** Do you still want **PCAP analysis**? Reply **yes** or **no**, or use the buttons. "
        "**JSM** and **status page** drafts are already in the tabs from this run."
    )

    return jsonify(
        {
            "success": True,
            "phase": "await_pcap_choice",
            "assistant_message": "\n\n".join(reply_lines),
            "validation_checks": validation_checks,
            "coverage": coverage,
            "coverage_file": cov_report,
            "similar_incidents": similar_incidents,
            "rag_error": rag_error,
            "templates": templates,
            "opensearch_report": opensearch_report,
            **session_payload(networks, os_narrative, cov_narrative),
        }
    )


@nexora_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"service": "nexora", "ok": True})
