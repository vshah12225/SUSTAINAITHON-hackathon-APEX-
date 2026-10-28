"""ImmuneFleet Supabase Database Client.
Supports both native REST (via standard library urllib, zero dependencies)
and the official supabase-py SDK if installed.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

# Attempt to load from streamlit secrets or env
def get_credentials():
    url = os.environ.get("SUPABASE_URL", "")
    key = os.environ.get("SUPABASE_KEY") or os.environ.get("SUPABASE_ANON_KEY") or os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or ""
    
    if not url or not key:
        try:
            import streamlit as st
            if hasattr(st, "secrets"):
                url = url or st.secrets.get("SUPABASE_URL", "")
                key = key or st.secrets.get("SUPABASE_KEY") or st.secrets.get("SUPABASE_ANON_KEY") or ""
        except Exception:
            pass
            
    return url.strip(), key.strip()


def is_configured():
    url, key = get_credentials()
    return bool(url and key)


def _api_request(endpoint, method="GET", payload=None, extra_headers=None):
    """Executes a direct PostgREST HTTP request to the Supabase database."""
    url, key = get_credentials()
    clean_url = url.strip().rstrip("/")
    if clean_url.endswith("/rest/v1"):
        clean_url = clean_url[:-8].rstrip("/")
        
    if not clean_url or not key:
        return None, "Supabase credentials not configured."
        
    full_url = f"{clean_url}/rest/v1/{endpoint.lstrip('/')}"
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)

    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(full_url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = resp.read()
            if not data:
                return {}, None
            return json.loads(data.decode("utf-8")), None
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        return None, f"HTTP {e.code}: {err_msg}"
    except Exception as e:
        return None, str(e)


def test_connection():
    """Validates connectivity to the Supabase instance."""
    url, key = get_credentials()
    if not url or not key:
        return False, "SUPABASE_URL or SUPABASE_KEY not provided."
    res, err = _api_request("antibodies?select=id&limit=1")
    if err:
        # Check if table just doesn't exist yet
        if "404" in err or "relation" in err.lower() or "does not exist" in err.lower():
            return True, "Connected to Supabase (run schema.sql to create tables)."
        return False, err
    return True, "Connected & verified."


def save_antibody(rule, signature):
    """Upserts a deployed antibody into the antibodies table."""
    if not is_configured():
        return False
    rule_id = f"{rule.get('target_id', '0x000')}:{rule.get('action', 'BLOCK')}:{rule.get('threat', 'ATTACK')}"
    payload = [{
        "id": rule_id,
        "target_id": str(rule.get("target_id", "")),
        "action": str(rule.get("action", "")),
        "threat": str(rule.get("threat", "")),
        "rule_json": rule,
        "signature": str(signature),
    }]
    # PostgREST merge-duplicates upsert
    headers = {
        "Prefer": "resolution=merge-duplicates,return=representation"
    }
    res, err = _api_request("antibodies", method="POST", payload=payload, extra_headers=headers)
    return err is None


def load_antibodies():
    """Loads all previously deployed antibodies from Supabase."""
    if not is_configured():
        return {}
    res, err = _api_request("antibodies?select=id,rule_json,signature")
    if err or not isinstance(res, list):
        return {}
    antibodies = {}
    for row in res:
        rk = row.get("id")
        rj = row.get("rule_json")
        sig = row.get("signature")
        if rk and rj and sig:
            rule_obj = rj if isinstance(rj, dict) else json.loads(rj)
            antibodies[rk] = {"rule": rule_obj, "sig": sig}
    return antibodies


def log_event(message, event_type="info"):
    """Appends an event to the cloud fleet_events table."""
    if not is_configured():
        return False
    payload = [{
        "message": str(message),
        "event_type": str(event_type),
    }]
    res, err = _api_request("fleet_events", method="POST", payload=payload)
    return err is None


def save_report(car_id, rule, signature):
    """Logs an incident detection report from an attacked vehicle."""
    if not is_configured():
        return False
    rule_id = f"{rule.get('target_id', '0x000')}:{rule.get('action', 'BLOCK')}:{rule.get('threat', 'ATTACK')}"
    payload = [{
        "car_id": int(car_id),
        "rule_key": rule_id,
        "signature": str(signature),
    }]
    res, err = _api_request("incident_reports", method="POST", payload=payload)
    return err is None


def fetch_antibodies_table(limit=10):
    """Fetches raw rows from the antibodies table for reviewer inspection."""
    if not is_configured():
        return []
    res, err = _api_request(f"antibodies?select=id,target_id,action,threat,signature,deployed_at&order=deployed_at.desc&limit={limit}")
    return res if isinstance(res, list) else []


def fetch_events_table(limit=5):
    """Fetches raw rows from the fleet_events audit trail for reviewer inspection."""
    if not is_configured():
        return []
    res, err = _api_request(f"fleet_events?select=id,message,event_type,created_at&order=id.desc&limit={limit}")
    return res if isinstance(res, list) else []

