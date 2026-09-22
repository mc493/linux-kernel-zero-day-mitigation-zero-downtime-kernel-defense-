#!/usr/bin/env python3
"""
Autonomous 360° GitHub Traffic & Telemetry Archiver (v1.0.0)
Defeats GitHub's 14-day data retention cliff by perpetually snapshotting
and merging repository traffic, clone telemetry, and web beacon hits.
"""

import os
import sys
import json
import datetime
import urllib.request
import urllib.error

REPO = os.getenv("GITHUB_REPOSITORY", "mc493/linux-kernel-zero-day-mitigation-zero-downtime-kernel-defense-")
TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "traffic")
HISTORY_FILE = os.path.join(DATA_DIR, "traffic_history.json")
SUMMARY_FILE = os.path.join(DATA_DIR, "SUMMARY.md")

USER_AGENT = "SovereignCluster-TrafficArchiver/1.0"


def fetch_json(url: str, token: str = "") -> dict:
    """Performs HTTP GET with proper headers."""
    headers = {"User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/vnd.github+json"
        
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"ℹ️ HTTP 403 on {url} (permission restricted or rate limited)")
        elif e.code == 404:
            print(f"ℹ️ HTTP 404 on {url}")
        else:
            print(f"⚠️ HTTP {e.code} on {url}: {e.reason}")
        return {}
    except Exception as e:
        print(f"⚠️ Request failed on {url}: {e}")
        return {}


def main():
    print(f"📊 Starting 360° Traffic Archiver for {REPO}...")
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # 1. Load existing history
    history = {
        "repository": REPO,
        "first_recorded": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "last_updated": "",
        "badge_hits": 0,
        "stars": 0,
        "forks": 0,
        "watchers": 0,
        "open_issues": 0,
        "daily_views": {},
        "daily_clones": {},
        "referrers": {}
    }
    
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                history.update(loaded)
                print(f"✅ Loaded existing history ({len(history.get('daily_views', {}))} days recorded)")
        except Exception as e:
            print(f"⚠️ Could not parse existing history file: {e}")

    # 2. Fetch Badge Hits (Public dwyl endpoint)
    badge_url = f"https://hits.dwyl.com/{REPO}.json"
    badge_data = fetch_json(badge_url)
    if badge_data and "message" in badge_data:
        try:
            badge_count = int(badge_data["message"])
            history["badge_hits"] = badge_count
            print(f"  -> Badge Hits: {badge_count:,}")
        except ValueError:
            pass

    # 3. Fetch Public Repo Metadata
    repo_url = f"https://api.github.com/repos/{REPO}"
    repo_meta = fetch_json(repo_url, token=TOKEN)
    if repo_meta and "stargazers_count" in repo_meta:
        history["stars"] = repo_meta.get("stargazers_count", 0)
        history["forks"] = repo_meta.get("forks_count", 0)
        history["watchers"] = repo_meta.get("subscribers_count", 0)
        history["open_issues"] = repo_meta.get("open_issues_count", 0)
        print(f"  -> Stars: {history['stars']} | Forks: {history['forks']} | Watchers: {history['watchers']}")

    # 4. Fetch Native Traffic (Requires Push or PAT permissions)
    if TOKEN:
        # Views
        views_url = f"https://api.github.com/repos/{REPO}/traffic/views"
        views_data = fetch_json(views_url, token=TOKEN)
        if views_data and "views" in views_data:
            for item in views_data["views"]:
                date_key = item["timestamp"][:10]
                history["daily_views"][date_key] = {
                    "count": item.get("count", 0),
                    "uniques": item.get("uniques", 0)
                }
            print(f"  -> Merged {len(views_data['views'])} daily view records from GitHub Traffic API")

        # Clones
        clones_url = f"https://api.github.com/repos/{REPO}/traffic/clones"
        clones_data = fetch_json(clones_url, token=TOKEN)
        if clones_data and "clones" in clones_data:
            for item in clones_data["clones"]:
                date_key = item["timestamp"][:10]
                history["daily_clones"][date_key] = {
                    "count": item.get("count", 0),
                    "uniques": item.get("uniques", 0)
                }
            print(f"  -> Merged {len(clones_data['clones'])} daily clone records from GitHub Traffic API")

        # Referrers
        ref_url = f"https://api.github.com/repos/{REPO}/traffic/popular/referrers"
        ref_data = fetch_json(ref_url, token=TOKEN)
        if isinstance(ref_data, list):
            for ref in ref_data:
                name = ref.get("referrer", "unknown")
                history["referrers"][name] = {
                    "count": ref.get("count", 0),
                    "uniques": ref.get("uniques", 0)
                }
            print(f"  -> Updated {len(ref_data)} referral sources")
    else:
        print("ℹ️ Note: No GITHUB_TOKEN provided; skipping private traffic/views endpoints.")

    # 5. Timestamp and Save JSON History
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    history["last_updated"] = now_iso
    
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, sort_keys=True)
    print(f"💾 Committed JSON time-series to {HISTORY_FILE}")

    # 6. Generate Markdown Summary
    generate_markdown_summary(history, SUMMARY_FILE)
    print(f"📄 Generated Markdown summary at {SUMMARY_FILE}")
    print("🏆 360° Traffic Archival Complete.")


def generate_markdown_summary(history: dict, summary_path: str):
    """Generates an executive traffic report in Markdown format."""
    total_views = sum(d.get("count", 0) for d in history["daily_views"].values())
    total_clones = sum(d.get("count", 0) for d in history["daily_clones"].values())
    
    lines = [
        f"# 📊 360° Repository Traffic & Telemetry History",
        f"",
        f"> **Repository:** [`{history['repository']}`](https://github.com/{history['repository']})  ",
        f"> **Last Updated:** `{history['last_updated']}` (UTC)  ",
        f"> **Archival Engine:** Automated Continuous Time-Series Ledger (Defeats GitHub 14-Day Cliff)",
        f"",
        f"---",
        f"",
        f"## 📈 Telemetry Scorecard",
        f"",
        f"| Metric | Total / Status | Description |",
        f"| :--- | :---: | :--- |",
        f"| **Live Badge Hits** | `{history.get('badge_hits', 0):,}` | Public visual hits via `hits.dwyl.com` web beacon |",
        f"| **Total Page Views** | `{total_views:,}` | Cumulative page views tracked via GitHub API |",
        f"| **Total Git Clones** | `{total_clones:,}` | Cumulative repository clones via CLI |",
        f"| **Stargazers** | `{history.get('stars', 0):,}` | Total GitHub stars |",
        f"| **Forks** | `{history.get('forks', 0):,}` | Total repository forks |",
        f"| **Watchers** | `{history.get('watchers', 0):,}` | Total subscribers |",
        f"",
        f"---",
        f"",
        f"## 📅 Daily Traffic Log",
        f"",
        f"| Date | Views (Total) | Views (Unique) | Clones (Total) | Clones (Unique) |",
        f"| :---: | :---: | :---: | :---: | :---: |"
    ]
    
    # Merge dates from views and clones
    all_dates = sorted(set(list(history["daily_views"].keys()) + list(history["daily_clones"].keys())), reverse=True)
    
    if not all_dates:
        # If no dates yet, record today as initial anchor
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        lines.append(f"| {today} | 0 | 0 | 0 | 0 |")
    else:
        for d in all_dates:
            v_cnt = history["daily_views"].get(d, {}).get("count", 0)
            v_unq = history["daily_views"].get(d, {}).get("uniques", 0)
            c_cnt = history["daily_clones"].get(d, {}).get("count", 0)
            c_unq = history["daily_clones"].get(d, {}).get("uniques", 0)
            lines.append(f"| `{d}` | {v_cnt:,} | {v_unq:,} | {c_cnt:,} | {c_unq:,} |")
            
    lines.extend([
        f"",
        f"---",
        f"",
        f"## 🌐 Top Referring Domains",
        f"",
        f"| Referrer | Views (Total) | Visitors (Unique) |",
        f"| :--- | :---: | :---: |"
    ])
    
    if not history["referrers"]:
        lines.append(f"| *No external referrers recorded yet* | 0 | 0 |")
    else:
        for ref_name, ref_data in sorted(history["referrers"].items(), key=lambda x: x[1].get("count", 0), reverse=True):
            lines.append(f"| **{ref_name}** | {ref_data.get('count', 0):,} | {ref_data.get('uniques', 0):,} |")
            
    lines.extend([
        f"",
        f"---",
        f"",
        f"*Maintained by Sovereign Cluster Autonomous Telemetry & SRE Engine.*"
    ])
    
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
