import hmac
import asyncio
import logging
from urllib.parse import quote
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from app.config import ADMIN_USERNAME, ADMIN_PASSWORD, BOT_TOKEN
from app.db import (
    init_db, list_reports, update_report, create_report, list_audit,
    create_enforcement_record, list_enforcement_records, update_enforcement_record,
    add_intel_indicator, list_intel_indicators, create_case_relation,
    list_case_relations, add_evidence_hash, list_evidence_hashes, list_case_events,
    create_blackshield_asset, list_blackshield_assets, update_blackshield_asset,
    create_blackshield_note, list_blackshield_notes
)
from app.intelligence import (
    validate_public_telegram_link, triage_hints, normalize_telegram_indicator,
    metadata_sha256, priority_assessment
)

app = FastAPI(title="AZOR CYBER DEFENCE · BLACKSHIELD", version="1.0.0")
security = HTTPBasic()

def require_admin(credentials: HTTPBasicCredentials = Depends(security)):
    if not ADMIN_PASSWORD or ADMIN_PASSWORD == "CHANGE_THIS_TO_A_LONG_RANDOM_PASSWORD":
        raise HTTPException(status_code=503, detail="Set a unique ADMIN_PASSWORD in .env")
    user_ok = hmac.compare_digest(credentials.username, ADMIN_USERNAME)
    pass_ok = hmac.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Invalid admin credentials",
                            headers={"WWW-Authenticate": "Basic"})
    return credentials.username

class StatusUpdate(BaseModel):
    status: str
    reviewer_note: str = Field(default="", max_length=1000)

class ManualReport(BaseModel):
    category: str = Field(min_length=3, max_length=100)
    target_type: str
    public_link: str = Field(default="", max_length=300)
    description: str = Field(min_length=15, max_length=2000)

class EnforcementStatusUpdate(BaseModel):
    status: str
    reviewer_note: str = Field(default="", max_length=1000)

class AuthorizedAssetInput(BaseModel):
    label: str = Field(min_length=2, max_length=120)
    asset_type: str
    scope: str = Field(min_length=3, max_length=500)
    owner: str = Field(min_length=2, max_length=120)
    authorization_basis: str = Field(min_length=10, max_length=1000)
    notes: str = Field(default="", max_length=1000)
    confirmed_authorized: bool

class BlackshieldNoteInput(BaseModel):
    report_id: int | None = None
    note_type: str
    reference: str = Field(min_length=3, max_length=500)
    observation: str = Field(min_length=10, max_length=2000)
    confidence: str = "unverified"

_telegram_task = None
_telegram_bot = None

@app.on_event("startup")
async def startup():
    global _telegram_task, _telegram_bot
    init_db()
    if BOT_TOKEN:
        from app.telegram_service import launch_bot
        _telegram_task, _telegram_bot = await launch_bot()
        logging.getLogger("azor").info("Telegram bot polling started.")
    else:
        logging.getLogger("azor").warning("BOT_TOKEN is not configured; Telegram bot is disabled.")

@app.on_event("shutdown")
async def shutdown():
    global _telegram_task, _telegram_bot
    if _telegram_task is not None:
        _telegram_task.cancel()
        try:
            await _telegram_task
        except asyncio.CancelledError:
            pass
        _telegram_task = None
    if _telegram_bot is not None:
        await _telegram_bot.session.close()
        _telegram_bot = None

@app.get("/", response_class=HTMLResponse)
def dashboard(_: str = Depends(require_admin)):
    return HTMLResponse(r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AZOR CYBER DEFENCE</title>
<style>
:root{color-scheme:dark;--bg:#080b16;--panel:#0e1322;--panel2:#121a2b;--panel3:#18233a;--line:#27334d;--text:#edf3ff;--muted:#8998b5;--blue:#4d7cff;--cyan:#36c6e8;--red:#f05a68;--amber:#e8b84f;--green:#28c88a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 50% -25%,#18254b 0,transparent 48%),var(--bg);color:var(--text);font:13px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Arial}
header{height:62px;display:flex;align-items:center;justify-content:space-between;padding:0 22px;background:rgba(7,10,20,.96);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:20}
.brand{display:flex;align-items:center;gap:10px;min-width:225px}.brand-mark{width:34px;height:34px;border:2px solid #9fb8ff;border-radius:10px;display:grid;place-items:center;color:#fff;font-weight:900;background:linear-gradient(145deg,#243f83,#111a33);box-shadow:0 0 20px #3155a733}
h1{font-size:14px;letter-spacing:.7px;margin:0;font-weight:800}.sub{font-size:9px;color:#8ea2ce;letter-spacing:1.2px;text-transform:uppercase}
.topnav{display:flex;align-items:center;gap:4px;flex:1;margin-left:28px;overflow:auto}.topnav .tab{padding:9px 13px;white-space:nowrap;border:0;background:transparent;color:#aab7d0;box-shadow:none;border-radius:7px}.topnav .tab.active{background:#18264a;color:#fff;box-shadow:inset 0 -2px #6b91ff}.topnav .tab:hover{background:#16213a;transform:none}
.header-right{display:flex;align-items:center;gap:12px}.private-pill{font-size:10px;color:#9de4ca;border:1px solid #235b4a;background:#0d2b25;padding:6px 9px;border-radius:20px;white-space:nowrap}.dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--green);margin-right:6px}
.wrap{max-width:1780px;margin:auto;padding:24px clamp(14px,2.7vw,42px) 42px}.page-heading{display:flex;justify-content:space-between;align-items:end;gap:16px;margin:0 0 18px}.page-heading h2{font-size:20px;margin:0 0 3px}.page-heading p{margin:0;color:var(--muted);font-size:12px}.eyebrow{color:#87a5ef;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;font-weight:700}
.grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}.card,.panel{background:linear-gradient(145deg,rgba(17,25,43,.98),rgba(11,16,30,.98));border:1px solid var(--line);border-radius:12px;padding:15px;box-shadow:0 8px 26px #0003;min-width:0}
.metric-card{display:flex;align-items:center;gap:13px;min-height:82px}.metric-icon{width:42px;height:42px;border-radius:50%;display:grid;place-items:center;color:#8fb0ff;background:#1a2c59;border:1px solid #304c8a;font-size:18px}.metric{font-size:25px;font-weight:800;letter-spacing:-.8px;line-height:1.15}.metric-label{font-size:11px;color:#9ba9c4;margin-top:4px}.metric-hint{font-size:9px;color:#6f83a9;text-transform:uppercase;letter-spacing:1px}
.tabs{display:flex;gap:3px;flex-wrap:wrap;margin:0;padding:0;width:auto}.tab{cursor:pointer}.hidden{display:none!important}
.overview-grid{display:grid;grid-template-columns:minmax(220px,255px) minmax(380px,1.2fr) minmax(350px,1.15fr);gap:13px;margin-top:13px;align-items:stretch}.stack{display:grid;gap:13px;align-content:start}.panel-title{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:12px}.panel-title h3{margin:0;font-size:12px;font-weight:700}.panel-title span{font-size:9px;color:var(--muted)}
.donut-wrap{display:grid;place-items:center;padding:10px 0}.donut{width:158px;height:158px;border-radius:50%;background:conic-gradient(var(--red) 0 var(--critical),var(--amber) var(--critical) var(--high),var(--blue) var(--high) 100%);position:relative;display:grid;place-items:center}.donut:after{content:"";position:absolute;inset:17px;background:#101729;border-radius:50%;border:1px solid #263653}.donut-center{position:relative;z-index:1;text-align:center}.donut-center strong{display:block;font-size:26px}.donut-center small{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.legend{display:grid;gap:8px;margin-top:8px}.legend-row{display:flex;justify-content:space-between;align-items:center;font-size:10px;color:#aebbd3}.legend-label{display:flex;align-items:center;gap:7px}.swatch{width:7px;height:7px;border-radius:50%;display:inline-block}
.overview-middle{display:grid;grid-template-rows:auto 1fr;gap:13px}.split-mini{display:grid;grid-template-columns:1fr 1fr;gap:10px}.mini-list{display:grid;gap:7px}.mini-row{display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:10px;color:#b5c2d9;padding-bottom:6px;border-bottom:1px solid #202b42}.count-pill{padding:2px 7px;border-radius:12px;background:#1c2a4c;color:#a9c4ff;font-size:9px}
.chart{width:100%;height:155px;display:block}.chart text{fill:#7f91b3;font-size:9px}.chart .gridline{stroke:#25314a;stroke-width:1}.chart .line{fill:none;stroke:var(--blue);stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}.chart .area{fill:url(#areaFill);opacity:.28}
.bar-list{display:grid;gap:10px}.bar-row{display:grid;grid-template-columns:95px 1fr 25px;gap:8px;align-items:center;font-size:10px;color:#aebbd3}.bar-track{height:7px;background:#1d2941;border-radius:10px;overflow:hidden}.bar-fill{height:100%;background:linear-gradient(90deg,#4267c8,#51bde9);border-radius:10px}
.network-box{height:180px;position:relative;overflow:hidden;border-radius:9px;background:radial-gradient(ellipse at center,#142449,#0c1323 72%);border:1px solid #202e4a}.network-box svg{width:100%;height:100%}.network-caption{font-size:9px;color:#7e91b5;margin-top:8px}
.danger{border:1px solid #663342;border-left:3px solid var(--red);padding:10px 13px;background:#291722;border-radius:8px;color:#e8b8c4;font-size:11px;margin-bottom:14px}
button,select,input,textarea{background:#131e34;color:var(--text);border:1px solid #314362;border-radius:7px;padding:9px 11px;font:inherit;outline:none}input:focus,textarea:focus,select:focus{border-color:#5b83e9;box-shadow:0 0 0 3px #4169c322}
button{background:linear-gradient(135deg,#4268c9,#29468e);border:1px solid #5278d7;cursor:pointer;font-weight:700;color:#fff;box-shadow:0 4px 13px #152e6a66}button:hover{filter:brightness(1.12);transform:translateY(-1px)}button:disabled{opacity:.45;cursor:not-allowed;transform:none}button.secondary{background:#17243d;border:1px solid #344b73;box-shadow:none}.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:13px 0}.toolbar input{flex:1;min-width:200px}
input,textarea{width:100%}label{display:block;color:#b6c4dc;margin:12px 0 5px;font-size:11px;font-weight:700}table{width:100%;border-collapse:separate;border-spacing:0;margin-top:12px;min-width:950px;font-size:12px}th,td{text-align:left;padding:11px;border-bottom:1px solid #24314a;vertical-align:top}th{color:#8eaefb;font-size:9px;text-transform:uppercase;letter-spacing:1px;background:#141e33;position:sticky;top:0}tbody tr:hover{background:#18243b}td{color:#d9e3f5}a{color:#8eb1ff;text-decoration:none}a:hover{text-decoration:underline}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:8px}
#notice{margin:12px 0;color:#9bb9ff;font-size:12px;min-height:18px}.preview{white-space:pre-wrap;overflow-wrap:anywhere;background:#0a1020;border:1px solid #293958;border-radius:8px;padding:14px;min-height:170px;color:#d7e4ff;font:11px/1.7 ui-monospace,Consolas,monospace}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.small{font-size:11px}.panel h2{font-size:16px;margin:0 0 7px}.panel h3{font-size:12px;margin:0 0 9px;color:#c5d5f4}.panel>p{font-size:11px;color:var(--muted)}.panel .card{box-shadow:none;background:#111a2b}
footer{border-top:1px solid var(--line);padding:15px 3%;color:#647594;font-size:10px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
@media(max-width:1200px){.overview-grid{grid-template-columns:220px 1fr}.overview-right{grid-column:1/-1;grid-template-columns:1fr 1fr}.grid{grid-template-columns:repeat(3,1fr)}}
@media(max-width:760px){header{height:auto;min-height:58px;padding:10px 13px;flex-wrap:wrap}.topnav{order:3;flex-basis:100%;margin:0}.brand{min-width:0}.overview-grid{grid-template-columns:1fr}.overview-right{grid-column:auto;grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.wrap{padding:17px 12px 30px}.page-heading{align-items:flex-start;flex-direction:column}.row{grid-template-columns:1fr}.private-pill{font-size:0}.private-pill .dot{margin:0}}

.detail-backdrop{position:fixed;inset:0;background:#030611d9;backdrop-filter:blur(8px);z-index:80;display:none;align-items:center;justify-content:center;padding:22px}
.detail-backdrop.open{display:flex}.detail-modal{width:min(1180px,100%);max-height:92vh;overflow:auto;background:#0d1424;border:1px solid #34466a;border-radius:15px;box-shadow:0 25px 90px #000b}
.detail-head{position:sticky;top:0;z-index:2;background:#101a2d;border-bottom:1px solid #2a3b5d;padding:17px 20px;display:flex;justify-content:space-between;gap:15px;align-items:center}
.detail-head h2{margin:0;font-size:17px}.detail-body{padding:18px;display:grid;grid-template-columns:minmax(0,1.5fr) minmax(270px,.8fr);gap:14px}
.detail-card{background:#111c30;border:1px solid #263858;border-radius:10px;padding:14px;min-width:0}.detail-card h3{margin:0 0 12px;color:#9bb8ff;font-size:11px;text-transform:uppercase;letter-spacing:1px}
.detail-main{display:grid;gap:12px}.detail-side{display:grid;gap:12px;align-content:start}.detail-kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:9px}.detail-kpi{padding:11px;background:#0c1528;border:1px solid #263858;border-radius:8px}.detail-kpi b{display:block;font-size:17px}.detail-kpi span{font-size:9px;color:#8ea1c4;text-transform:uppercase}
.detail-value{font-size:12px;color:#d8e3f8;white-space:pre-wrap;overflow-wrap:anywhere}.detail-muted{font-size:10px;color:#8a9bb9}.detail-list{display:grid;gap:8px}.detail-item{padding:9px 10px;background:#0c1528;border:1px solid #223250;border-radius:7px;font-size:11px;color:#cbd8ef}.detail-item small{display:block;color:#7f94b8;margin-top:3px}
.pill{display:inline-block;border-radius:20px;padding:3px 8px;font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.5px;background:#1d3155;color:#a9c6ff}.pill.critical{background:#49202c;color:#ff9aa8}.pill.high{background:#49381d;color:#f5d18b}.pill.normal{background:#1c3151;color:#9fc0ff}
.detail-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.detail-close{background:#1b2942;border:1px solid #3a4d70;box-shadow:none}.detail-empty{font-size:11px;color:#8193b3;padding:8px 0}
@media(max-width:760px){.detail-backdrop{padding:7px}.detail-modal{max-height:96vh}.detail-body{grid-template-columns:1fr;padding:11px}.detail-kpis{grid-template-columns:1fr 1fr}.detail-head{padding:13px}}
</style></head><body>
<header>
<div class="brand"><div class="brand-mark">A</div><div><h1>AZOR CYBER DEFENCE</h1><div class="sub">Threat intelligence operations</div></div></div>
<nav class="topnav">
<button class="tab active" data-tab="overview">Dashboard</button>
<button class="tab" data-tab="cases">Cases</button>
<button class="tab" data-tab="add">New Report</button>
<button class="tab" data-tab="intel">Threat Intel</button>
<button class="tab" data-tab="blackshield">Blackshield</button>
<button class="tab" data-tab="enforce">Enforcement</button>
<button class="tab" data-tab="audit">Activities</button>
<button class="tab" data-tab="cli">Kali CLI</button>
</nav>
<div class="header-right"><div class="private-pill"><span class="dot"></span> PRIVATE</div></div>
</header>
<div class="wrap">
<div class="page-heading"><div><div class="eyebrow">Security operations center / overview</div><h2>Threat Intelligence Dashboard</h2><p>Live overview of reported abuse, investigation workload and enforcement activity.</p></div><div class="small muted" id="lastUpdated">Waiting for data…</div></div>
<div class="danger">Human-reviewed reports only. AZOR does not automatically ban Telegram accounts or submit mass reports. Never upload, download, forward or store intimate media or suspected child sexual abuse material.</div>
<div class="grid">
<div class="card metric-card"><div class="metric-icon">◎</div><div><div class="metric" id="total">—</div><div class="metric-label">Total reports</div><div class="metric-hint">All recorded cases</div></div></div>
<div class="card metric-card"><div class="metric-icon">◷</div><div><div class="metric" id="new">—</div><div class="metric-label">New reports</div><div class="metric-hint">Awaiting review</div></div></div>
<div class="card metric-card"><div class="metric-icon">⌕</div><div><div class="metric" id="reviewing">—</div><div class="metric-label">Under review</div><div class="metric-hint">Investigation queue</div></div></div>
<div class="card metric-card"><div class="metric-icon">↗</div><div><div class="metric" id="drafts">—</div><div class="metric-label">Enforcement drafts</div><div class="metric-hint">Prepared submissions</div></div></div>
<div class="card metric-card"><div class="metric-icon">✓</div><div><div class="metric" id="actioned">—</div><div class="metric-label">Action recorded</div><div class="metric-hint">Platform response logged</div></div></div>
</div>
<section id="overview" class="overview-grid">
<div class="stack">
<div class="panel"><div class="panel-title"><h3>Case priority distribution</h3><span>Heuristic review</span></div><div class="donut-wrap"><div class="donut" id="priorityDonut" style="--critical:0%;--high:0%"><div class="donut-center"><strong id="priorityTotal">0</strong><small>Reports</small></div></div></div><div class="legend" id="priorityLegend"></div></div>
<div class="panel"><div class="panel-title"><h3>Target breakdown</h3><span>By reported type</span></div><div id="targetBars" class="bar-list"></div></div>
</div>
<div class="overview-middle">
<div class="panel"><div class="panel-title"><h3>Case activity trend</h3><span>Last 7 days · recorded cases</span></div><svg class="chart" id="trendChart" viewBox="0 0 600 170" preserveAspectRatio="none" aria-label="Case activity trend"></svg></div>
<div class="panel"><div class="panel-title"><h3>Investigation network</h3><span>Recorded case relationships</span></div><div class="network-box"><svg id="networkGraph" viewBox="0 0 600 180" role="img" aria-label="Related case network"></svg></div><div class="network-caption">Nodes represent cases; links represent exact public-indicator matches. Connections are leads for human review, not identity attribution.</div></div>
</div>
<div class="stack overview-right">
<div class="panel"><div class="panel-title"><h3>Recent case activity</h3><button class="secondary" onclick="switchTab('cases')">View cases</button></div><div class="mini-list" id="recentCases"></div></div>
<div class="panel"><div class="panel-title"><h3>Enforcement status</h3><span>Submission tracking</span></div><div id="enforcementBars" class="bar-list"></div></div>
</div>
</section>
<section id="cases" class="panel hidden">
<h2>Case queue</h2><div class="toolbar"><input id="search" placeholder="Search case ID, description, category or link"><select id="statusFilter"><option value="">All statuses</option><option>new</option><option>reviewing</option><option>submitted_to_platform</option><option>referred_to_authority</option><option>closed</option><option>false_positive</option></select><button id="refresh">Refresh</button></div>
<div class="tablewrap"><table><thead><tr><th>Case</th><th>Category / target</th><th>Source</th><th>Public link</th><th>Description</th><th>Status</th><th>Reviewer note</th><th>Save</th></tr></thead><tbody id="rows"></tbody></table></div>
</section>
<section id="add" class="panel hidden"><h2>Record public observation</h2><p class="muted">Record only information you lawfully observed or are authorized to moderate. No private-group scraping, access bypass, purchases or engagement.</p>
<form id="manualForm">
<label>Category</label><select id="category"><option>Non-consensual intimate content</option><option>Suspected sexual deepfake</option><option>Leaked private imagery</option><option>Sexual content involving a suspected minor</option><option>Other exploitation / sale activity</option></select>
<label>Target type</label><select id="target"><option value="group">Group</option><option value="channel">Channel</option><option value="bot">Bot</option><option value="account">Account</option></select>
<label>Public Telegram URL (optional)</label><input id="link" placeholder="https://t.me/public_channel_or_post">
<label>Text-only observation (15–2,000 characters)</label><textarea id="description" rows="5" minlength="15" maxlength="2000" placeholder="Describe the public listing or conduct observed. Do not include explicit descriptions."></textarea>
<p><button type="submit">Create case</button></p></form><div id="triage"></div>
</section>
<section id="enforce" class="panel hidden">
<h2>External platform reporting</h2>
<p class="muted">Choose a case to prepare a factual complaint. The tool does not submit reports or determine violations. Review the draft, verify every link and submit it yourself.</p>
<div class="row">
<div><label>Case ID</label><select id="enforceCase"><option value="">Select a case</option></select></div>
<div><label>Reporting route</label><select id="route"><option value="abuse_email">Telegram abuse email — public content</option><option value="in_app">Telegram in-app message report</option><option value="victim_tidabot">Victim / authorized representative — @TIDABot</option></select></div>
</div>
<div class="toolbar"><button id="prepare">Prepare complaint draft</button><button class="secondary" id="copyDraft" disabled>Copy draft</button><button class="secondary" id="openMail" disabled>Open email draft</button><a id="openTida" class="hidden" href="https://t.me/TIDABot" target="_blank" rel="noopener">Open @TIDABot</a></div>
<div id="draftPreview" class="preview">Select a case and prepare a draft. No media uploads are accepted or needed.</div>
<div id="routeHelp" class="muted small" style="margin-top:10px">For public content, Telegram's FAQ directs users to in-app reporting or abuse@telegram.org. Include public t.me links and specific message links.</div>
<h3>Submission tracking</h3>
<div class="row">
<div><label>Enforcement record</label><select id="enforcementRecord"><option value="">Select a prepared report</option></select></div>
<div><label>Outcome status</label><select id="enforcementStatus"><option value="prepared">Prepared — not submitted</option><option value="submitted">Submitted by investigator</option><option value="acknowledged">Acknowledged</option><option value="action_taken">Action taken</option><option value="no_action">No action reported</option><option value="needs_more_info">More information requested</option><option value="withdrawn">Withdrawn</option></select></div>
</div>
<label>Investigator note / reference number</label><input id="enforcementNote" maxlength="1000" placeholder="Optional: submission date, reference ID, response summary">
<button id="saveEnforcement" style="margin-top:10px">Save enforcement update</button>
<div id="enforcementHistory" style="margin-top:16px"></div>
</section>
<section id="intel" class="panel hidden">
<h2>Threat Intelligence Engine</h2>
<p class="muted">Record public Telegram indicators you lawfully observed, correlate exact matches across cases, assess review priority and preserve hashes of text metadata only. No crawling, private-group access or media collection.</p>
<div class="row">
<div><label>Case</label><select id="intelCase"><option value="">Select case</option></select></div>
<div><label>Public indicator (@username or t.me link)</label><input id="intelValue" placeholder="@publicchannel or https://t.me/publicchannel/123"></div>
</div>
<div class="toolbar"><button id="addIndicator">Add indicator</button><button class="secondary" id="correlate">Find exact matches</button><button class="secondary" id="assessPriority">Assess review priority</button><button class="secondary" id="hashMetadata">Hash case metadata</button></div>
<div class="row">
<div class="card"><h3>Indicators</h3><div id="indicatorResults" class="small muted">Select a case.</div></div>
<div class="card"><h3>Related cases</h3><div id="relationResults" class="small muted">No correlation run yet.</div></div>
</div>
<div class="row" style="margin-top:12px">
<div class="card"><h3>Priority assessment</h3><div id="priorityResults" class="small muted">No assessment run yet.</div></div>
<div class="card"><h3>Metadata integrity hashes</h3><div id="hashResults" class="small muted">No hash generated yet.</div></div>
</div>
<h3>Case activity timeline</h3><div id="intelTimeline" class="small muted">Select a case to view activity.</div>
</section>

<section id="blackshield" class="panel hidden">
 <div class="page-heading"><div><div class="eyebrow">AZOR BLACKSHIELD · v1.0</div><h2>Authorized Security & Public Intelligence Workspace</h2><p>Register assets you are permitted to assess, keep public-source notes and prepare a controlled assessment plan.</p></div><span class="pill normal">SAFE MODE</span></div>
 <div class="danger">No third-party hacking, bot takeover, private-group access, disruption, scraping or automated reporting. Adding an asset records your stated authorization; it does not verify ownership. Do not test anything outside the exact written scope.</div>
 <div class="row">
  <div class="card"><h3>Register an authorized asset</h3>
   <label>Asset label</label><input id="bsLabel" placeholder="My lab web application">
   <label>Asset type</label><select id="bsType"><option value="web_app">Web application</option><option value="domain">Domain</option><option value="ip_host">IP / host</option><option value="api">API</option><option value="lab_vm">Lab VM</option><option value="owned_bot">Bot I own</option></select>
   <label>Exact authorized scope</label><input id="bsScope" placeholder="https://staging.example.test or 192.168.56.10">
   <label>Owner / organization</label><input id="bsOwner" placeholder="My lab / organization">
   <label>Authorization basis (who granted permission, date, limits)</label><textarea id="bsAuth" rows="3" placeholder="I own this lab system; testing permitted from ... to ..."></textarea>
   <label>Notes / exclusions</label><textarea id="bsNotes" rows="2" placeholder="Out-of-scope systems, test window, contact..."></textarea>
   <label><input id="bsConfirm" type="checkbox" style="width:auto"> I own this asset or have explicit written permission for this exact scope.</label>
   <button id="bsAddAsset">Register asset</button>
  </div>
  <div class="card"><h3>Public-source intelligence note</h3>
   <label>Related case (optional)</label><select id="bsCase"><option value="">No linked case</option></select>
   <label>Source type</label><select id="bsNoteType"><option value="public_telegram">Public Telegram reference</option><option value="public_web">Public web page</option><option value="platform_response">Platform response</option><option value="other_public">Other public source</option></select>
   <label>Public reference (URL or citation)</label><input id="bsReference" placeholder="https://t.me/public_channel/123">
   <label>Factual, non-explicit observation</label><textarea id="bsObservation" rows="4" placeholder="Record what was publicly visible, when observed, and why it may be relevant. Avoid intimate details or media."></textarea>
   <label>Confidence</label><select id="bsConfidence"><option value="unverified">Unverified lead</option><option value="corroborated">Corroborated public information</option><option value="official">Official platform / authority response</option></select>
   <button id="bsAddNote">Save intelligence note</button>
  </div>
 </div>
 <div class="row" style="margin-top:14px"><div class="card"><h3>Authorized asset register</h3><div id="bsAssets" class="detail-list">Loading…</div></div><div class="card"><h3>Public intelligence log</h3><div id="bsNotes" class="detail-list">Loading…</div></div></div>
 <div class="card" style="margin-top:14px"><h3>Safe assessment workflow</h3><ol class="small"><li>Confirm written authorization and exact scope before testing.</li><li>Use a lab or staging environment where possible.</li><li>Start with passive configuration review and dependency/version inventory.</li><li>Use non-destructive checks; avoid credential attacks, persistence, data extraction or denial of service.</li><li>Record findings, impact, reproduction steps and remediation.</li><li>Stop immediately if scope is unclear or unexpected access to real user data occurs.</li></ol><p class="muted">Blackshield v1.0 is a registry and case-management layer. It does not launch scans or exploit attempts.</p></div>
</section>

<section id="cli" class="panel hidden">
 <div class="panel-title"><h3>Kali Linux Investigation Workstation</h3><span>AZOR CLI · v1.0</span></div>
 <p class="muted">The terminal tool and this dashboard share the same local SQLite database when both are run from this project folder with the same DATABASE_PATH setting.</p>
 <div class="danger">The CLI validates and records public references only. It does not scrape Telegram, access private groups, exploit bots, mass-report accounts, or perform takedowns. All external complaints require investigator review and manual submission.</div>
 <div class="row">
  <div class="card"><h3>Quick commands</h3>
   <label>Validate a public Telegram reference</label><pre class="preview">python azor_cli.py inspect https://t.me/public_channel/123</pre>
   <label>List recent cases</label><pre class="preview">python azor_cli.py cases --limit 20</pre>
   <label>Inspect a case</label><pre class="preview">python azor_cli.py case-show 1</pre>
   <label>Create a case</label><pre class="preview">python azor_cli.py case-add --target channel --category "Suspected sexual deepfake" --link "https://t.me/public_channel/123" --description "Public listing observed; manual review required."</pre>
  </div>
  <div class="card"><h3>Investigation & reporting</h3>
   <label>Add a public indicator</label><pre class="preview">python azor_cli.py indicator-add 1 @publicchannel</pre>
   <label>Correlate exact matches</label><pre class="preview">python azor_cli.py correlate 1</pre>
   <label>Prepare a complaint draft</label><pre class="preview">python azor_cli.py draft 1 --route abuse_email</pre>
   <label>Export case metadata</label><pre class="preview">python azor_cli.py export 1 --format json --out exports/case-1.json</pre>
  </div>
 </div>
 <div class="card" style="margin-top:12px"><h3>Kali VM setup</h3>
  <pre class="preview">chmod +x install_kali.sh
./install_kali.sh
source .venv/bin/activate
python azor_cli.py --help</pre>
  <p class="muted">For true integration, run the CLI and dashboard inside the same Kali VM, from the same project folder, using the same local DATABASE_PATH. Do not put the live SQLite database on a network share.</p>
 </div>
</section>

<section id="audit" class="panel hidden"><h2>Recent audit activity</h2><div id="auditRows"></div></section>
<div id="notice" role="status"></div>
</div>

<div id="detailBackdrop" class="detail-backdrop" role="dialog" aria-modal="true" aria-labelledby="detailTitle">
 <div class="detail-modal">
  <div class="detail-head"><div><div class="eyebrow">Investigation workspace</div><h2 id="detailTitle">Alert details</h2></div><button class="detail-close" id="closeDetail">Close ✕</button></div>
  <div class="detail-body">
   <div class="detail-main">
    <div class="detail-card"><h3>Incident overview</h3><div class="detail-kpis" id="detailKpis"></div><div style="margin-top:13px"><div class="detail-muted">Description / observation</div><div class="detail-value" id="detailDescription"></div></div><div style="margin-top:12px"><div class="detail-muted">Public target reference</div><div class="detail-value" id="detailLink"></div></div></div>
    <div class="detail-card"><h3>Indicators & related cases</h3><div class="row"><div><div class="detail-muted">Recorded indicators</div><div id="detailIndicators" class="detail-list"></div></div><div><div class="detail-muted">Correlated cases</div><div id="detailRelations" class="detail-list"></div></div></div></div>
    <div class="detail-card"><h3>Investigation timeline</h3><div id="detailTimeline" class="detail-list"></div></div>
   </div>
   <div class="detail-side">
    <div class="detail-card"><h3>Analyst actions</h3><label>Case status</label><select id="detailStatus"><option>new</option><option>reviewing</option><option>submitted_to_platform</option><option>referred_to_authority</option><option>closed</option><option>false_positive</option></select><label>Investigator note</label><textarea id="detailNote" rows="4" maxlength="1000" placeholder="Record factual review notes…"></textarea><div class="detail-actions"><button id="saveDetail">Save changes</button><button class="secondary" id="openDetailEnforce">Prepare report</button></div></div>
    <div class="detail-card"><h3>Platform enforcement</h3><div id="detailEnforcement" class="detail-list"></div></div>
    <div class="detail-card"><h3>Metadata integrity</h3><div id="detailHashes" class="detail-list"></div></div>
    <div class="detail-card"><h3>Priority assessment</h3><div id="detailPriority" class="detail-value"></div><div class="detail-muted" style="margin-top:6px">Review-priority heuristic only; not a finding of wrongdoing.</div></div>
   </div>
  </div>
 </div>
</div>

<footer><span>AZOR CYBER DEFENCE · PRIVATE INVESTIGATION WORKSPACE</span><span>Human-reviewed intelligence · No automated enforcement</span></footer>
<script>
const $=id=>document.getElementById(id);let cases=[],currentDraft=null;
function notice(t){$('notice').textContent=t}
function switchTab(id){
 document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x.dataset.tab===id));
 ['overview','cases','add','enforce','intel','audit','cli'].forEach(name=>{const el=$(name);if(el)el.classList.toggle('hidden',name!==id)});
 if(id==='blackshield')loadBlackshield();if(id==='audit')loadAudit();if(id==='enforce')loadEnforcementCases();if(id==='intel')loadIntelCases();if(id==='overview')loadOverview();
}
document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>switchTab(b.dataset.tab)));

function svgEl(tag,attrs={}){const e=document.createElementNS('http://www.w3.org/2000/svg',tag);Object.entries(attrs).forEach(([k,v])=>e.setAttribute(k,v));return e}
function renderTrend(data){
 const svg=$('trendChart');svg.replaceChildren();const W=600,H=170,L=30,R=12,T=12,B=25;
 for(let i=0;i<4;i++){const y=T+i*(H-T-B)/3;svg.appendChild(svgEl('line',{x1:L,y1:y,x2:W-R,y2:y,class:'gridline'}))}
 const max=Math.max(1,...data.map(x=>x.count));const pts=data.map((x,i)=>({x:L+i*(W-L-R)/Math.max(1,data.length-1),y:T+(H-T-B)*(1-x.count/max)}));
 if(pts.length){let path='M '+pts.map(p=>p.x+' '+p.y).join(' L ');let area=path+' L '+pts[pts.length-1].x+' '+(H-B)+' L '+pts[0].x+' '+(H-B)+' Z';svg.appendChild(svgEl('path',{d:area,class:'area'}));svg.appendChild(svgEl('path',{d:path,class:'line'}))}
 data.forEach((x,i)=>{let p=pts[i];svg.appendChild(svgEl('circle',{cx:p.x,cy:p.y,r:3,fill:'#83a5ff'}));let t=svgEl('text',{x:p.x,y:H-7,'text-anchor':'middle'});t.textContent=x.label;svg.appendChild(t)});
}
function renderBars(elId,items){
 const el=$(elId);el.replaceChildren();const max=Math.max(1,...items.map(x=>x.count));
 items.forEach(x=>{const row=document.createElement('div');row.className='bar-row';const label=document.createElement('span');label.textContent=x.label;const track=document.createElement('div');track.className='bar-track';const fill=document.createElement('div');fill.className='bar-fill';fill.style.width=(x.count/max*100)+'%';track.appendChild(fill);const count=document.createElement('b');count.textContent=x.count;row.append(label,track,count);el.appendChild(row)});
 if(!items.length){el.textContent='No records yet.'}
}
async function loadOverview(){
 const r=await fetch('/api/overview');if(!r.ok)return;const d=await r.json();
 $('total').textContent=d.total;$('new').textContent=d.new;$('reviewing').textContent=d.reviewing;$('drafts').textContent=d.drafts;$('actioned').textContent=d.actioned;$('priorityTotal').textContent=d.total;
 $('lastUpdated').textContent='Updated '+new Date().toLocaleTimeString();
 const p=d.priority;const total=Math.max(1,d.total);const critical=p.critical/total*100;const high=(p.high+p.critical)/total*100;
 $('priorityDonut').style.setProperty('--critical',critical+'%');$('priorityDonut').style.setProperty('--high',high+'%');
 const legend=$('priorityLegend');legend.replaceChildren();
 [['Critical',p.critical,'var(--red)'],['High',p.high,'var(--amber)'],['Normal',p.normal,'var(--blue)']].forEach(x=>{const row=document.createElement('div');row.className='legend-row';const left=document.createElement('span');left.className='legend-label';const sw=document.createElement('i');sw.className='swatch';sw.style.background=x[2];left.append(sw,document.createTextNode(x[0]));const val=document.createElement('b');val.textContent=x[1];row.append(left,val);legend.append(row)});
 renderBars('targetBars',d.targets);renderBars('enforcementBars',d.enforcement);renderTrend(d.trend);
 const recent=$('recentCases');recent.replaceChildren();d.recent.forEach(x=>{const row=document.createElement('div');row.className='mini-row';const label=document.createElement('span');label.textContent='#'+x.id+' · '+x.target_type+' · '+x.category;const badge=document.createElement('span');badge.className='count-pill';badge.textContent=x.status;row.append(label,badge);recent.append(row)});if(!d.recent.length)recent.textContent='No cases recorded yet.';
 const graph=$('networkGraph');graph.replaceChildren();const nodes=d.graph.nodes,edges=d.graph.edges;const pos={};nodes.forEach((n,i)=>{const angle=(Math.PI*2*i/Math.max(1,nodes.length))-(Math.PI/2);pos[n.id]={x:300+Math.cos(angle)*190,y:90+Math.sin(angle)*62}});
 edges.forEach(e=>{if(pos[e.a]&&pos[e.b])graph.appendChild(svgEl('line',{x1:pos[e.a].x,y1:pos[e.a].y,x2:pos[e.b].x,y2:pos[e.b].y,stroke:'#4b72d0','stroke-width':1.5,opacity:.75}))});
 nodes.forEach(n=>{const p=pos[n.id];const c=svgEl('circle',{cx:p.x,cy:p.y,r:10,fill:n.linked?'#4f82ff':'#263a64',stroke:n.linked?'#91b3ff':'#526d9d','stroke-width':1.5});graph.appendChild(c);const t=svgEl('text',{x:p.x,y:p.y+3,'text-anchor':'middle',fill:'#fff','font-size':8});t.textContent=n.id;graph.appendChild(t)});
 if(!nodes.length){const t=svgEl('text',{x:300,y:95,'text-anchor':'middle',fill:'#8497bd','font-size':12});t.textContent='No case relationships recorded';graph.appendChild(t)}
}

function cell(tr,value){const td=document.createElement('td');td.textContent=value??'';tr.appendChild(td);return td}

let activeDetailId=null;
function detailItem(container,title,meta=''){
 const el=document.createElement('div');el.className='detail-item';el.textContent=title;
 if(meta){const sm=document.createElement('small');sm.textContent=meta;el.appendChild(sm)}
 container.appendChild(el);
}
function detailValue(id,value){$(id).textContent=value??'—'}
async function openCaseDetail(id){
 const r=await fetch('/api/cases/'+id+'/detail');const d=await r.json();
 if(!r.ok){notice(d.detail||'Could not load case details.');return}
 activeDetailId=id;const c=d.report,p=d.priority;
 $('detailTitle').textContent='Case #'+c.id+' · '+c.category;
 const k=$('detailKpis');k.replaceChildren();
 [['STATUS',c.status],['TARGET',c.target_type],['PRIORITY',p.priority.toUpperCase()]].forEach((x,i)=>{
  const box=document.createElement('div');box.className='detail-kpi';const b=document.createElement('b');b.textContent=x[1];if(i===2){const pill=document.createElement('span');pill.className='pill '+p.priority;pill.textContent=x[1];box.appendChild(pill)}else box.appendChild(b);
  const span=document.createElement('span');span.textContent=x[0];box.appendChild(span);k.appendChild(box);
 });
 detailValue('detailDescription',c.description);
 const link=$('detailLink');link.replaceChildren();
 if(c.public_link){const a=document.createElement('a');a.href=c.public_link;a.target='_blank';a.rel='noopener noreferrer';a.textContent=c.public_link;link.appendChild(a)}else link.textContent='No public link recorded';
 $('detailStatus').value=c.status;$('detailNote').value=c.reviewer_note||'';
 const indicators=$('detailIndicators');indicators.replaceChildren();d.indicators.forEach(x=>detailItem(indicators,x.display_value,x.indicator_type+' · '+x.created_at));if(!d.indicators.length)indicators.textContent='No indicators recorded.';
 const relations=$('detailRelations');relations.replaceChildren();d.relations.forEach(x=>detailItem(relations,'Case #'+(x.case_a===id?x.case_b:x.case_a),x.reason));if(!d.relations.length)relations.textContent='No correlated cases.';
 const timeline=$('detailTimeline');timeline.replaceChildren();d.events.forEach(x=>detailItem(timeline,x.event_type.replaceAll('_',' ')+': '+x.details,x.created_at+' · '+x.actor));if(!d.events.length)timeline.textContent='No timeline events.';
 const enforcement=$('detailEnforcement');enforcement.replaceChildren();d.enforcement.forEach(x=>detailItem(enforcement,'#'+x.id+' · '+x.status,x.destination+' · '+x.updated_at));if(!d.enforcement.length)enforcement.textContent='No enforcement records.';
 const hashes=$('detailHashes');hashes.replaceChildren();d.hashes.forEach(x=>detailItem(hashes,x.algorithm.toUpperCase()+' · '+x.digest,x.description));if(!d.hashes.length)hashes.textContent='No metadata hashes.';
 $('detailPriority').textContent=p.score+'/100 · '+p.reasons.join(' · ');
 $('detailBackdrop').classList.add('open');document.body.style.overflow='hidden';
}
function closeCaseDetail(){$('detailBackdrop').classList.remove('open');document.body.style.overflow='';activeDetailId=null}
$('closeDetail').onclick=closeCaseDetail;
$('detailBackdrop').addEventListener('click',e=>{if(e.target===$('detailBackdrop'))closeCaseDetail()});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeCaseDetail()});
$('saveDetail').onclick=async()=>{
 if(!activeDetailId)return;const r=await fetch('/api/reports/'+activeDetailId+'/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:$('detailStatus').value,reviewer_note:$('detailNote').value})});
 const d=await r.json();notice(r.ok?'Case #'+activeDetailId+' updated.':(d.detail||'Update failed.'));
 if(r.ok){await openCaseDetail(activeDetailId);load();loadOverview()}
};
$('openDetailEnforce').onclick=()=>{const id=activeDetailId;closeCaseDetail();switchTab('enforce');loadEnforcementCases().then(()=>$('enforceCase').value=String(id))};

async function load(){
 const q=$('search').value;const st=$('statusFilter').value;
 const r=await fetch('/api/reports?query='+encodeURIComponent(q)+'&status='+encodeURIComponent(st));
 if(!r.ok){notice('Unable to load reports.');return}
 cases=await r.json();$('total').textContent=cases.length;
 $('new').textContent=cases.filter(x=>x.status==='new').length;
 $('reviewing').textContent=cases.filter(x=>x.status==='reviewing').length;
 const body=$('rows');body.replaceChildren();
 for(const x of cases){
  const tr=document.createElement('tr');const caseCell=cell(tr,'');const viewBtn=document.createElement('button');viewBtn.className='secondary';viewBtn.textContent='View #'+x.id;viewBtn.onclick=()=>openCaseDetail(x.id);caseCell.append(viewBtn);const date=document.createElement('div');date.className='detail-muted';date.textContent=new Date(x.created_at).toLocaleString();caseCell.append(date);
  cell(tr,x.category+' / '+x.target_type);cell(tr,x.source==='public_observation'?'Public observation':'Community report');
  const linktd=document.createElement('td');
  if(x.public_link){const a=document.createElement('a');a.textContent='Open link';a.href=x.public_link.startsWith('http')?x.public_link:'https://'+x.public_link;a.target='_blank';a.rel='noopener noreferrer';linktd.appendChild(a)}else linktd.textContent='—';
  tr.appendChild(linktd);cell(tr,x.description);
  const std=cell(tr,'');const sel=document.createElement('select');
  ['new','reviewing','submitted_to_platform','referred_to_authority','closed','false_positive'].forEach(s=>{const o=document.createElement('option');o.value=s;o.textContent=s;o.selected=s===x.status;sel.appendChild(o)});std.appendChild(sel);
  const noted=cell(tr,'');const note=document.createElement('textarea');note.rows=2;note.maxLength=1000;note.value=x.reviewer_note||'';noted.appendChild(note);
  const act=cell(tr,'');const btn=document.createElement('button');btn.textContent='Save';btn.onclick=async()=>{
   const res=await fetch('/api/reports/'+x.id+'/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:sel.value,reviewer_note:note.value})});
   notice(res.ok?'Case #'+x.id+' updated.':'Update failed.');if(res.ok)load();
  };act.appendChild(btn);body.appendChild(tr);
 }
}
async function loadEnforcementCases(){
 const r=await fetch('/api/reports');if(!r.ok)return;const data=await r.json();const sel=$('enforceCase');const previous=sel.value;sel.replaceChildren(new Option('Select a case',''));
 data.forEach(x=>sel.add(new Option('#'+x.id+' · '+x.target_type+' · '+x.category,x.id)));
 if(previous)sel.value=previous;
 const er=await fetch('/api/enforcement');if(er.ok){const records=await er.json();$('drafts').textContent=records.length;const rs=$('enforcementRecord');const old=rs.value;rs.replaceChildren(new Option('Select a prepared report',''));records.forEach(x=>rs.add(new Option('#'+x.id+' · case #'+x.report_id+' · '+x.status,x.id)));if(old)rs.value=old;}
}
$('enforceCase').onchange=()=>{currentDraft=null;$('draftPreview').textContent='Prepare a new complaint draft for the selected case.';$('copyDraft').disabled=true;$('openMail').disabled=true;$('openTida').classList.add('hidden')};
$('route').onchange=()=>{
 const route=$('route').value;
 $('routeHelp').textContent=route==='victim_tidabot'
 ?'Use this route only when the intimate image/video concerns the victim and the reporter is the victim or an authorized representative. Do not upload or forward the media to AZOR.'
 :route==='in_app'
 ?'In Telegram Desktop, right-click the specific violating message, choose Report, select the closest reason and submit. Repeat only for distinct, relevant messages.'
 :'Telegram’s FAQ lists abuse@telegram.org for illegal public content. Include exact public t.me links or @usernames. Do not attach intimate media.';
};
$('prepare').onclick=async()=>{
 const id=$('enforceCase').value;if(!id){notice('Select a case first.');return}
 const r=await fetch('/api/enforcement/draft/'+id+'?route='+encodeURIComponent($('route').value));
 const data=await r.json();if(!r.ok){notice(data.detail||'Could not prepare draft.');return}
 currentDraft=data;$('draftPreview').textContent='TO: '+data.to+'\\nSUBJECT: '+data.subject+'\\n\\n'+data.body+'\\n\\n---\\nSubmission route: '+data.route_label+'\\n'+data.instructions;
 $('copyDraft').disabled=false;$('openMail').disabled=data.route!=='abuse_email';
 $('openTida').classList.toggle('hidden',data.route!=='victim_tidabot');
 notice('Draft prepared. Review the allegations and links before submission.');
 const save=await fetch('/api/enforcement/drafts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({report_id:Number(id),route:data.route,subject:data.subject,body:data.body})});
 if(save.ok){const rec=await save.json();$('enforcementRecord').value=rec.id;loadEnforcementCases();}
};
$('copyDraft').onclick=async()=>{if(!currentDraft)return;await navigator.clipboard.writeText('To: '+currentDraft.to+'\\nSubject: '+currentDraft.subject+'\\n\\n'+currentDraft.body);notice('Complaint draft copied.');};
$('openMail').onclick=()=>{if(!currentDraft)return;const url='mailto:'+currentDraft.to+'?subject='+encodeURIComponent(currentDraft.subject)+'&body='+encodeURIComponent(currentDraft.body);window.location.href=url;};
$('saveEnforcement').onclick=async()=>{
 const id=$('enforcementRecord').value;if(!id){notice('Select an enforcement record.');return}
 const r=await fetch('/api/enforcement/'+id+'/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:$('enforcementStatus').value,reviewer_note:$('enforcementNote').value})});
 const d=await r.json();notice(r.ok?'Enforcement record updated.':(d.detail||'Update failed.'));if(r.ok){loadEnforcementCases();loadEnforcementHistory();}
};
$('enforcementRecord').onchange=loadEnforcementHistory;
async function loadEnforcementHistory(){
 const id=$('enforcementRecord').value;if(!id)return;const r=await fetch('/api/enforcement');if(!r.ok)return;const records=await r.json();const x=records.find(v=>String(v.id)===String(id));if(!x)return;
 $('enforcementStatus').value=x.status;$('enforcementNote').value=x.reviewer_note||'';
 $('enforcementHistory').textContent='Prepared '+new Date(x.created_at).toLocaleString()+' · Updated '+new Date(x.updated_at).toLocaleString()+' · Destination: '+x.destination;
}
async function loadAudit(){const r=await fetch('/api/audit');if(!r.ok)return;const data=await r.json();const box=$('auditRows');box.replaceChildren();for(const x of data){const p=document.createElement('p');p.textContent=x.created_at+' · '+x.actor+' · '+x.action+' · case '+(x.report_id??'—');box.appendChild(p)}}
$('refresh').onclick=load;$('statusFilter').onchange=load;$('search').oninput=()=>{clearTimeout(window._searchTimer);window._searchTimer=setTimeout(load,250)};
$('manualForm').onsubmit=async e=>{e.preventDefault();const payload={category:$('category').value,target_type:$('target').value,public_link:$('link').value.trim(),description:$('description').value.trim()};
 const r=await fetch('/api/reports/public-observation',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
 const data=await r.json();if(!r.ok){notice(data.detail||'Could not create case.');return}
 $('triage').textContent='Case #'+data.report_id+' created. '+data.hints.join(' ');$('manualForm').reset();notice('Public observation recorded.');load();
};

async function loadIntelCases(){
 const r=await fetch('/api/reports');if(!r.ok)return;const data=await r.json();
 const sel=$('intelCase'),old=sel.value;sel.replaceChildren(new Option('Select case',''));
 data.forEach(x=>sel.add(new Option('#'+x.id+' · '+x.target_type+' · '+x.category,x.id)));
 if(old)sel.value=old;if(sel.value)loadIntelCase();
}
$('intelCase').onchange=loadIntelCase;
async function loadIntelCase(){
 const id=$('intelCase').value;if(!id)return;
 const [ir,rr,tr,hr]=await Promise.all([
  fetch('/api/intel/indicators?report_id='+id),fetch('/api/intel/relations/'+id),
  fetch('/api/intel/timeline/'+id),fetch('/api/intel/hashes/'+id)]);
 if(ir.ok){const d=await ir.json();$('indicatorResults').textContent=d.length?d.map(x=>x.indicator_type+': '+x.display_value).join('\\n'):'No indicators recorded.'}
 if(rr.ok){const d=await rr.json();$('relationResults').textContent=d.length?d.map(x=>'Case #'+(x.case_a==id?x.case_b:x.case_a)+' — '+x.reason).join('\\n'):'No exact-match relationships.'}
 if(tr.ok){const d=await tr.json();$('intelTimeline').textContent=d.length?d.map(x=>x.created_at+' · '+x.event_type+' · '+x.details).join('\\n'):'No events recorded yet.'}
 if(hr.ok){const d=await hr.json();$('hashResults').textContent=d.length?d.map(x=>x.algorithm.toUpperCase()+': '+x.digest+' ('+x.description+')').join('\\n'):'No metadata hashes generated.'}
}
$('addIndicator').onclick=async()=>{
 const id=$('intelCase').value,val=$('intelValue').value.trim();if(!id||!val){notice('Select a case and enter a public indicator.');return}
 const r=await fetch('/api/intel/indicators',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({report_id:Number(id),value:val})});
 const d=await r.json();notice(r.ok?'Public indicator recorded.':(d.detail||'Could not add indicator.'));if(r.ok){$('intelValue').value='';loadIntelCase();}
};
$('correlate').onclick=async()=>{
 const id=$('intelCase').value;if(!id){notice('Select a case first.');return}
 const r=await fetch('/api/intel/correlate/'+id,{method:'POST'});const d=await r.json();
 notice(r.ok?'Correlation complete. '+d.created+' new relationship(s).':(d.detail||'Correlation failed.'));if(r.ok)loadIntelCase();
};
$('assessPriority').onclick=async()=>{
 const id=$('intelCase').value;if(!id){notice('Select a case first.');return}
 const r=await fetch('/api/intel/priority/'+id);const d=await r.json();
 $('priorityResults').textContent=r.ok?'Priority: '+d.priority.toUpperCase()+' ('+d.score+'/100)\\n'+d.reasons.join('\\n')+'\\n'+d.disclaimer:(d.detail||'Assessment failed.');
};
$('hashMetadata').onclick=async()=>{
 const id=$('intelCase').value;if(!id){notice('Select a case first.');return}
 const r=await fetch('/api/intel/hash/'+id,{method:'POST'});const d=await r.json();
 notice(r.ok?'Metadata SHA-256 recorded.':(d.detail||'Hash failed.'));if(r.ok)loadIntelCase();
};

async function loadBlackshield(){
 const [ar,nr,cr]=await Promise.all([fetch('/api/blackshield/assets'),fetch('/api/blackshield/notes'),fetch('/api/reports')]);
 if(!ar.ok||!nr.ok)return;const assets=await ar.json(),notes=await nr.json();cases=await cr.json();
 const cs=$('bsCase');cs.replaceChildren(new Option('No linked case',''));cases.forEach(c=>cs.add(new Option('#'+c.id+' · '+c.category,c.id)));
 const ae=$('bsAssets');ae.replaceChildren();assets.forEach(a=>{const d=document.createElement('div');d.className='detail-item';d.textContent='#'+a.id+' · '+a.label+' ['+a.status+']';const sm=document.createElement('small');sm.textContent=a.asset_type+' · '+a.scope+' · Owner: '+a.owner+' · '+a.authorization_basis;d.append(sm);const b=document.createElement('button');b.className='secondary';b.style.marginTop='7px';b.textContent=a.status==='active'?'Pause scope':'Reactivate scope';b.onclick=async()=>{const r=await fetch('/api/blackshield/assets/'+a.id+'/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:a.status==='active'?'paused':'active'})});if(r.ok)loadBlackshield()};d.append(b);ae.append(d)});if(!assets.length)ae.textContent='No authorized assets registered.';
 const ne=$('bsNotes');ne.replaceChildren();notes.forEach(n=>{const d=document.createElement('div');d.className='detail-item';d.textContent=(n.report_id?'Case #'+n.report_id+' · ':'')+n.note_type+' · '+n.confidence;const sm=document.createElement('small');sm.textContent=n.reference+'\\n'+n.observation+'\\n'+n.created_at;d.append(sm);ne.append(d)});if(!notes.length)ne.textContent='No public intelligence notes.';
}
$('bsAddAsset').onclick=async()=>{if(!$('bsConfirm').checked){notice('Confirm ownership or written authorization first.');return}const payload={label:$('bsLabel').value,asset_type:$('bsType').value,scope:$('bsScope').value,owner:$('bsOwner').value,authorization_basis:$('bsAuth').value,notes:$('bsNotes').value,confirmed_authorized:true};const r=await fetch('/api/blackshield/assets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const d=await r.json();notice(r.ok?'Authorized scope registered as asset #'+d.id+'.':(d.detail||'Could not register asset.'));if(r.ok){['bsLabel','bsScope','bsOwner','bsAuth','bsNotes'].forEach(x=>$(x).value='');$('bsConfirm').checked=false;loadBlackshield()}};
$('bsAddNote').onclick=async()=>{const payload={report_id:$('bsCase').value?Number($('bsCase').value):null,note_type:$('bsNoteType').value,reference:$('bsReference').value,observation:$('bsObservation').value,confidence:$('bsConfidence').value};const r=await fetch('/api/blackshield/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const d=await r.json();notice(r.ok?'Public intelligence note saved as #'+d.id+'.':(d.detail||'Could not save note.'));if(r.ok){$('bsReference').value='';$('bsObservation').value='';loadBlackshield()}};

load();loadOverview();
</script></body></html>
""")


@app.get("/api/overview")
def overview(_: str = Depends(require_admin)):
    from datetime import datetime, timedelta, timezone
    reports = list_reports(limit=500)
    records = list_enforcement_records()
    total = len(reports)
    statuses = [x["status"] for x in reports]
    priority = {"critical": 0, "high": 0, "normal": 0}
    targets = {"group": 0, "channel": 0, "bot": 0, "account": 0}
    for item in reports:
        priority[priority_assessment(item)["priority"]] += 1
        if item["target_type"] in targets:
            targets[item["target_type"]] += 1
    enforcement = {k: 0 for k in ["prepared","submitted","acknowledged","action_taken","no_action","needs_more_info","withdrawn"]}
    for item in records:
        if item["status"] in enforcement:
            enforcement[item["status"]] += 1
    today = datetime.now(timezone.utc).date()
    trend = []
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        count = sum(1 for x in reports if (x.get("created_at") or "")[:10] == day.isoformat())
        trend.append({"label": day.strftime("%a"), "count": count})
    relations = []
    nodeset = set()
    # Keep graph legible and limit the overview to recent cases and their direct relations.
    recent_ids = {x["id"] for x in reports[:24]}
    for rid in recent_ids:
        for rel in list_case_relations(rid):
            a, b = rel["case_a"], rel["case_b"]
            if a in recent_ids and b in recent_ids and (a,b) not in relations and (b,a) not in relations:
                relations.append((a,b)); nodeset.update([a,b])
    graph_nodes = [{"id": i, "linked": True} for i in sorted(nodeset)]
    if not graph_nodes:
        graph_nodes = [{"id": x["id"], "linked": False} for x in reports[:8]]
    return {
        "total": total,
        "new": statuses.count("new"),
        "reviewing": statuses.count("reviewing"),
        "drafts": sum(1 for x in records if x["status"] == "prepared"),
        "actioned": sum(1 for x in records if x["status"] == "action_taken"),
        "priority": priority,
        "targets": [{"label": k.title(), "count": v} for k,v in targets.items() if v],
        "enforcement": [{"label": k.replace("_"," ").title(), "count": v} for k,v in enforcement.items() if v],
        "trend": trend,
        "recent": [{"id": x["id"], "target_type": x["target_type"], "category": x["category"], "status": x["status"]} for x in reports[:6]],
        "graph": {"nodes": graph_nodes, "edges": [{"a": a, "b": b} for a,b in relations]}
    }

@app.get("/api/reports")
def reports(query: str = Query(default="", max_length=100),
            status: str = Query(default="", max_length=50),
            _: str = Depends(require_admin)):
    return list_reports(query=query.strip() or None, status=status or None)

@app.post("/api/reports/public-observation")
def add_public_observation(payload: ManualReport, actor: str = Depends(require_admin)):
    if payload.target_type not in {"group", "channel", "bot", "account"}:
        raise HTTPException(status_code=400, detail="Invalid target type")
    if not validate_public_telegram_link(payload.public_link):
        raise HTTPException(status_code=400, detail="Only public t.me links are accepted")
    report_id = create_report(
        reporter_id=None, category=payload.category, target_type=payload.target_type,
        public_link=payload.public_link, description=payload.description,
        source="public_observation", actor=actor
    )
    return {"ok": True, "report_id": report_id,
            "hints": triage_hints(payload.category, payload.description)}


@app.get("/api/cases/{report_id}/detail")
def case_detail(report_id: int, _: str = Depends(require_admin)):
    case = next((x for x in list_reports(limit=500) if x["id"] == report_id), None)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return {
        "report": case,
        "priority": priority_assessment(case),
        "indicators": list_intel_indicators(report_id),
        "relations": list_case_relations(report_id),
        "events": list_case_events(report_id),
        "hashes": list_evidence_hashes(report_id),
        "enforcement": list_enforcement_records(report_id=report_id)
    }

@app.get("/api/enforcement/draft/{report_id}")
def enforcement_draft(report_id: int, route: str = Query(default="abuse_email"),
                      actor: str = Depends(require_admin)):
    rows = list_reports(limit=500)
    case = next((x for x in rows if x["id"] == report_id), None)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if route not in {"abuse_email", "in_app", "victim_tidabot"}:
        raise HTTPException(status_code=400, detail="Invalid reporting route")
    if route == "victim_tidabot" and case["category"] not in {
        "Non-consensual intimate content", "Suspected sexual deepfake", "Leaked private imagery"
    }:
        raise HTTPException(status_code=400, detail="This route is reserved for intimate-image cases reported by the victim or an authorized representative.")
    target = case.get("public_link") or "[Add the exact public Telegram link or @username]"
    subject = f"Report of potentially illegal Telegram content — AZOR case #{report_id}"
    body = (
        "Hello Telegram Moderation Team,\\n\\n"
        "I am submitting this report for human review of potentially illegal content on Telegram. "
        "The information below is based on an observation and is an allegation, not a finding.\\n\\n"
        f"Target type: {case['target_type']}\\n"
        f"Reported public link / identifier: {target}\\n"
        f"Concern category: {case['category']}\\n"
        f"Text-only description: {case['description']}\\n"
        f"AZOR case reference: #{report_id}\\n\\n"
        "Please review the linked public content under Telegram's applicable policies and take any action you consider appropriate. "
        "No intimate images or videos are attached to this report.\\n\\n"
        "Regards,\\nAZOR CYBER DEFENCE investigator"
    )
    if route == "victim_tidabot":
        to = "@TIDABot"
        route_label = "Telegram @TIDABot — victim / authorized representative pathway"
        instructions = "Telegram's FAQ identifies @TIDABot for a non-consensual intimate image/video concerning the victim. Use only if you are the victim or an authorized representative. This draft is a prompt, not an automated bot submission."
    elif route == "in_app":
        to = "Telegram in-app Report"
        route_label = "In-app message report"
        instructions = "Open the specific message in Telegram Desktop, right-click, choose Report, select the relevant reason and add a concise explanation. This draft is for reference; it is not sent automatically."
    else:
        to = "abuse@telegram.org"
        route_label = "Email to Telegram abuse team"
        instructions = "Review and send this email yourself. Include precise public t.me links or @usernames. Do not attach intimate media or suspected child sexual abuse material."
    return {"report_id": report_id, "route": route, "to": to, "subject": subject,
            "body": body, "route_label": route_label, "instructions": instructions}

class EnforcementDraft(BaseModel):
    report_id: int
    route: str
    subject: str = Field(min_length=5, max_length=200)
    body: str = Field(min_length=20, max_length=8000)

@app.post("/api/enforcement/drafts")
def save_enforcement_draft(payload: EnforcementDraft, actor: str = Depends(require_admin)):
    destinations = {"abuse_email": "abuse@telegram.org", "in_app": "Telegram in-app Report", "victim_tidabot": "@TIDABot"}
    if payload.route not in destinations:
        raise HTTPException(status_code=400, detail="Invalid reporting route")
    record_id = create_enforcement_record(payload.report_id, payload.subject, payload.body,
                                          destinations[payload.route], actor)
    if record_id is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"ok": True, "id": record_id}

@app.get("/api/enforcement")
def enforcement_records(_: str = Depends(require_admin)):
    return list_enforcement_records()

@app.post("/api/enforcement/{record_id}/status")
def enforcement_status(record_id: int, payload: EnforcementStatusUpdate,
                       actor: str = Depends(require_admin)):
    try:
        found = update_enforcement_record(record_id, payload.status, payload.reviewer_note, actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not found:
        raise HTTPException(status_code=404, detail="Enforcement record not found")
    return {"ok": True, "id": record_id, "status": payload.status}

@app.get("/api/audit")
def audit(_: str = Depends(require_admin)):
    return list_audit()


class IndicatorInput(BaseModel):
    report_id: int
    value: str = Field(min_length=3, max_length=300)

@app.post("/api/intel/indicators")
def add_indicator(payload: IndicatorInput, actor: str = Depends(require_admin)):
    try:
        kind, normalized, display = normalize_telegram_indicator(payload.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    indicator_id = add_intel_indicator(payload.report_id, kind, normalized, display, actor)
    if indicator_id is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"ok": True, "indicator_id": indicator_id, "type": kind, "normalized": normalized}

@app.get("/api/intel/indicators")
def get_indicators(report_id: int | None = None, _: str = Depends(require_admin)):
    return list_intel_indicators(report_id)

@app.post("/api/intel/correlate/{report_id}")
def correlate_cases(report_id: int, actor: str = Depends(require_admin)):
    reports = list_reports(limit=500)
    if not any(x["id"] == report_id for x in reports):
        raise HTTPException(status_code=404, detail="Case not found")
    # Seed this case's existing public link as an indicator if one is present.
    case = next(x for x in reports if x["id"] == report_id)
    if case.get("public_link"):
        try:
            kind, normalized, display = normalize_telegram_indicator(case["public_link"])
            add_intel_indicator(report_id, kind, normalized, display, actor)
        except ValueError:
            pass
    indicators = list_intel_indicators()
    target_values = {x["normalized_value"] for x in indicators if x["report_id"] == report_id}
    if not target_values:
        return {"ok": True, "created": 0, "message": "Add a public indicator before correlating."}
    matches = {}
    for item in indicators:
        if item["normalized_value"] in target_values and item["report_id"] != report_id:
            matches.setdefault(item["report_id"], set()).add(item["normalized_value"])
    created = 0
    for other_id, values in matches.items():
        reason = "Exact public Telegram indicator match: " + ", ".join(sorted(values))[:150]
        before = len(list_case_relations(report_id))
        create_case_relation(report_id, other_id, reason)
        after = len(list_case_relations(report_id))
        if after > before:
            created += 1
    return {"ok": True, "created": created, "matched_cases": sorted(matches.keys())}

@app.get("/api/intel/relations/{report_id}")
def get_relations(report_id: int, _: str = Depends(require_admin)):
    return list_case_relations(report_id)

@app.get("/api/intel/priority/{report_id}")
def get_priority(report_id: int, _: str = Depends(require_admin)):
    case = next((x for x in list_reports(limit=500) if x["id"] == report_id), None)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return priority_assessment(case)

@app.post("/api/intel/hash/{report_id}")
def hash_case_metadata(report_id: int, actor: str = Depends(require_admin)):
    case = next((x for x in list_reports(limit=500) if x["id"] == report_id), None)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    digest = metadata_sha256(case)
    hash_id = add_evidence_hash(report_id, digest, "Case text metadata only; no media files", actor)
    return {"ok": True, "hash_id": hash_id, "algorithm": "sha256", "digest": digest}

@app.get("/api/intel/hashes/{report_id}")
def get_hashes(report_id: int, _: str = Depends(require_admin)):
    return list_evidence_hashes(report_id)

@app.get("/api/intel/timeline/{report_id}")
def get_timeline(report_id: int, _: str = Depends(require_admin)):
    return list_case_events(report_id)

@app.post("/api/reports/{report_id}/status")
def set_status(report_id: int, payload: StatusUpdate, actor: str = Depends(require_admin)):
    try:
        found = update_report(report_id, payload.status, payload.reviewer_note, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not found:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"ok": True, "report_id": report_id, "status": payload.status}


@app.get("/api/blackshield/assets")
def blackshield_assets(_: str = Depends(require_admin)):
    return list_blackshield_assets()

@app.post("/api/blackshield/assets")
def blackshield_add_asset(payload: AuthorizedAssetInput, actor: str = Depends(require_admin)):
    if not payload.confirmed_authorized:
        raise HTTPException(status_code=400, detail="Explicit ownership or written authorization confirmation is required")
    if payload.asset_type not in {"web_app","domain","ip_host","api","lab_vm","owned_bot"}:
        raise HTTPException(status_code=400, detail="Invalid asset type")
    asset_id=create_blackshield_asset(payload.label,payload.asset_type,payload.scope,payload.owner,
                                      payload.authorization_basis,payload.notes,actor)
    return {"ok":True,"id":asset_id,"message":"Scope recorded; authorization has not been independently verified."}

class AssetStatusUpdate(BaseModel):
    status: str

@app.post("/api/blackshield/assets/{asset_id}/status")
def blackshield_asset_status(asset_id: int, payload: AssetStatusUpdate, actor: str = Depends(require_admin)):
    try: found=update_blackshield_asset(asset_id,payload.status,actor)
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc))
    if not found: raise HTTPException(status_code=404,detail="Asset not found")
    return {"ok":True,"id":asset_id,"status":payload.status}

@app.get("/api/blackshield/notes")
def blackshield_notes(_: str = Depends(require_admin)):
    return list_blackshield_notes()

@app.post("/api/blackshield/notes")
def blackshield_add_note(payload: BlackshieldNoteInput, actor: str = Depends(require_admin)):
    if payload.note_type not in {"public_telegram","public_web","platform_response","other_public"}:
        raise HTTPException(status_code=400,detail="Invalid source type")
    if payload.confidence not in {"unverified","corroborated","official"}:
        raise HTTPException(status_code=400,detail="Invalid confidence")
    if payload.note_type=="public_telegram" and not validate_public_telegram_link(payload.reference):
        raise HTTPException(status_code=400,detail="Only public t.me references are accepted for Telegram notes")
    note_id=create_blackshield_note(payload.report_id,payload.note_type,payload.reference,payload.observation,payload.confidence,actor)
    if note_id is None: raise HTTPException(status_code=404,detail="Linked case not found")
    return {"ok":True,"id":note_id}
