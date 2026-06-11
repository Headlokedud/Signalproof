"""SignalProof logger — receives TradingView alert webhooks and writes them
to an append-only, hash-chained SQLite log."""
import csv
import io
import json
import os
import sqlite3
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

import hashlib

GENESIS = "GENESIS"

FIELDS = [
    "received_at", "indicator", "symbol", "exchange", "interval",
    "signal", "price_raw", "bar_time", "alert_time", "raw",
]


def row_hash(prev_hash: str, row: dict) -> str:
    """Canonical hash for one signal row. `row` values may be None."""
    parts = [prev_hash or GENESIS]
    for f in FIELDS:
        v = row.get(f)
        parts.append("" if v is None else str(v))
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def verify_chain(rows: list) -> dict:
    """Walk rows (ascending insert order) and recompute the chain."""
    prev = GENESIS
    for i, r in enumerate(rows):
        if (r.get("prev_hash") or GENESIS) != prev:
            return {"intact": False, "checked": i, "first_bad_index": i}
        expect = row_hash(prev, r)
        if r.get("row_hash") != expect:
            return {"intact": False, "checked": i, "first_bad_index": i}
        prev = r["row_hash"]
    return {"intact": True, "checked": len(rows), "first_bad_index": None}

DB_PATH = os.environ.get("SP_DB", "signalproof.db")
SECRET = os.environ.get("SP_SECRET", "change-me")

app = FastAPI(title="SignalProof Logger", version="0.1.0")

SCHEMA = """
CREATE TABLE IF NOT EXISTS signals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    indicator   TEXT NOT NULL,
    symbol      TEXT,
    exchange    TEXT,
    interval    TEXT,
    signal      TEXT,
    price_raw   TEXT,
    price       REAL,
    bar_time    TEXT,
    alert_time  TEXT,
    raw         TEXT,
    prev_hash   TEXT NOT NULL,
    row_hash    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_signals_indicator ON signals (indicator, id);
"""

COLUMNS = [
    "id", "received_at", "indicator", "symbol", "exchange", "interval",
    "signal", "price_raw", "bar_time", "alert_time", "raw",
    "prev_hash", "row_hash",
]


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


@app.on_event("startup")
def init_db() -> None:
    conn = db()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    if SECRET == "change-me":
        print("[SignalProof] WARNING: SP_SECRET is the default. "
              "Set SP_SECRET before exposing this server.")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.get("/health")
def health() -> dict:
    return {"ok": True, "time": utcnow_iso()}


@app.post("/webhook/{secret}")
async def webhook(secret: str, request: Request) -> JSONResponse:
    if secret != SECRET:
        raise HTTPException(status_code=403, detail="bad secret")

    raw_bytes = await request.body()
    raw = raw_bytes.decode("utf-8", errors="replace").strip()
    payload: dict = {}
    parsed = False
    try:
        loaded = json.loads(raw)
        if isinstance(loaded, dict):
            payload, parsed = loaded, True
    except (ValueError, TypeError):
        pass

    price_raw = payload.get("price")
    price_raw = None if price_raw is None else str(price_raw)
    try:
        price = float(price_raw) if price_raw not in (None, "") else None
    except ValueError:
        price = None

    row = {
        "received_at": utcnow_iso(),
        "indicator": str(payload.get("indicator") or "unknown"),
        "symbol": _opt(payload.get("symbol")),
        "exchange": _opt(payload.get("exchange")),
        "interval": _opt(payload.get("interval")),
        "signal": _opt(payload.get("signal")),
        "price_raw": price_raw,
        "bar_time": _opt(payload.get("bar_time")),
        "alert_time": _opt(payload.get("alert_time")),
        "raw": raw,
    }

    conn = db()
    try:
        cur = conn.execute(
            "SELECT row_hash FROM signals WHERE indicator = ? "
            "ORDER BY id DESC LIMIT 1",
            (row["indicator"],),
        )
        last = cur.fetchone()
        prev = last["row_hash"] if last else GENESIS
        rhash = row_hash(prev, row)
        conn.execute(
            "INSERT INTO signals (received_at, indicator, symbol, exchange, "
            "interval, signal, price_raw, price, bar_time, alert_time, raw, "
            "prev_hash, row_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (row["received_at"], row["indicator"], row["symbol"],
             row["exchange"], row["interval"], row["signal"],
             row["price_raw"], price, row["bar_time"], row["alert_time"],
             row["raw"], prev, rhash),
        )
        conn.commit()
    finally:
        conn.close()

    return JSONResponse({"ok": True, "parsed_json": parsed,
                         "indicator": row["indicator"], "row_hash": rhash})


def _opt(v):
    if v is None:
        return None
    s = str(v).strip()
    return s or None


@app.get("/indicators")
def indicators() -> list:
    conn = db()
    try:
        cur = conn.execute(
            "SELECT indicator, COUNT(*) AS n, MIN(received_at) AS first_seen, "
            "MAX(received_at) AS last_seen FROM signals "
            "GROUP BY indicator ORDER BY last_seen DESC"
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


@app.get("/signals")
def signals(indicator: str | None = None,
            fmt: str = Query("json", pattern="^(json|csv)$"),
            limit: int = Query(100000, ge=1, le=1000000)):
    conn = db()
    try:
        if indicator:
            cur = conn.execute(
                "SELECT * FROM signals WHERE indicator = ? ORDER BY id "
                "LIMIT ?", (indicator, limit))
        else:
            cur = conn.execute(
                "SELECT * FROM signals ORDER BY id LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    if fmt == "json":
        return JSONResponse(rows)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    buf.seek(0)
    name = f"signalproof_{indicator or 'all'}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={name}"})


@app.get("/verify/{indicator}")
def verify(indicator: str) -> dict:
    conn = db()
    try:
        cur = conn.execute(
            "SELECT * FROM signals WHERE indicator = ? ORDER BY id",
            (indicator,))
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    if not rows:
        raise HTTPException(status_code=404, detail="no rows for indicator")
    result = verify_chain(rows)
    result.update({
        "indicator": indicator,
        "first_received": rows[0]["received_at"],
        "last_received": rows[-1]["received_at"],
        "last_hash": rows[-1]["row_hash"],
    })
    return result


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    conn = db()
    try:
        recent = [dict(r) for r in conn.execute(
            "SELECT received_at, indicator, symbol, interval, signal, "
            "price_raw, bar_time FROM signals ORDER BY id DESC LIMIT 50")]
        counts = [dict(r) for r in conn.execute(
            "SELECT indicator, COUNT(*) n FROM signals GROUP BY indicator "
            "ORDER BY n DESC")]
    finally:
        conn.close()

    def esc(v):
        s = "" if v is None else str(v)
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;"))

    chips = "".join(
        f'<span class="chip">{esc(c["indicator"])} '
        f'<b>{c["n"]}</b></span>' for c in counts) or \
        '<span class="chip">no signals logged yet</span>'
    rows = "".join(
        "<tr>" + "".join(
            f"<td>{esc(r[k])}</td>" for k in
            ("received_at", "indicator", "symbol", "interval",
             "signal", "price_raw", "bar_time")) + "</tr>"
        for r in recent) or '<tr><td colspan="7">Waiting for the first ' \
        'webhook. Point a TradingView alert at /webhook/&lt;secret&gt;.</td></tr>'

    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SignalProof logger</title><style>
:root {{ --paper:#ECEFF3; --ink:#0F1B2D; --muted:#5A6B85; --line:#C6CFDB; --panel:#FAFBFD; }}
body {{ margin:0; background:var(--paper); color:var(--ink);
  font:14px/1.5 "IBM Plex Mono", ui-monospace, Menlo, monospace; padding:32px 20px; }}
h1 {{ font:900 22px/1.1 Archivo, system-ui, sans-serif; letter-spacing:.04em;
  text-transform:uppercase; margin:0 0 4px; }}
p {{ color:var(--muted); margin:0 0 20px; }}
.chip {{ display:inline-block; background:var(--panel); border:1px solid var(--line);
  padding:4px 10px; margin:0 8px 8px 0; border-radius:999px; }}
table {{ width:100%; border-collapse:collapse; background:var(--panel);
  border:2px solid var(--ink); }}
th, td {{ text-align:left; padding:7px 10px; border-bottom:1px solid var(--line);
  font-size:12.5px; white-space:nowrap; }}
th {{ text-transform:uppercase; letter-spacing:.08em; font-size:11px;
  border-bottom:2px solid var(--ink); }}
.wrap {{ max-width:1100px; margin:0 auto; }} .scroll {{ overflow-x:auto; }}
</style></head><body><div class="wrap">
<h1>SignalProof · live signal log</h1>
<p>Append-only, hash-chained record of every alert this server receives. Server time is the evidence.</p>
<div>{chips}</div>
<div class="scroll"><table><thead><tr><th>received (UTC)</th><th>indicator</th>
<th>symbol</th><th>tf</th><th>signal</th><th>price</th><th>bar time</th></tr></thead>
<tbody>{rows}</tbody></table></div>
</div></body></html>"""
