from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from collections import Counter
import json
import importlib
import sqlite3
from detection import DetectionEngine, FeatureRecord
from database import get_db_connection
from models import Flow, Stats, TimelinePoint, FlowDetail, ModuleStats, ForensicsStats, ActionableEvent, FeatureIngestRequest, ResolutionRequest, IngestRequest, IngestModuleResult
from control_plane import router as control_plane_router, compat_router as control_plane_compat_router

import os

app = FastAPI(title="AegisNet API")
app.include_router(control_plane_router)
app.include_router(control_plane_compat_router)


def _detect_ws_backend() -> Optional[str]:
    for module_name in ("websockets", "wsproto"):
        try:
            importlib.import_module(module_name)
            return module_name
        except Exception:
            continue
    return None


@app.on_event("startup")
def ensure_websocket_backend_available() -> None:
    ws_backend = _detect_ws_backend()
    if not ws_backend:
        raise RuntimeError(
            "No WebSocket backend is available for Uvicorn/FastAPI. "
            "Install dependencies with: pip install 'uvicorn[standard]'"
        )

# Enable CORS for React frontend
_cors_origins = os.getenv("AEGIS_CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health_check():
    return {"status": "ok", "ws_backend": _detect_ws_backend() or "missing"}

@app.get("/api/stats", response_model=Stats)
def get_stats():
    conn = get_db_connection()
    try:
        # Total flows
        total = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        
        # Malicious flows
        malicious = conn.execute("SELECT COUNT(*) FROM flows WHERE verdict = 'malicious'").fetchone()[0]
        
        # Avg Severity
        avg_sev = conn.execute("SELECT AVG(severity) FROM flows").fetchone()[0] or 0.0
        
        # Top Attackers List
        top_attackers_rows = conn.execute("""
            SELECT src_ip, COUNT(*) as cnt 
            FROM flows 
            WHERE verdict = 'malicious' 
            GROUP BY src_ip 
            ORDER BY cnt DESC 
            LIMIT 5
        """).fetchall()
        top_attackers = [{"ip": row["src_ip"], "count": row["cnt"]} for row in top_attackers_rows]
        
        top_src = top_attackers[0]["ip"] if top_attackers else "N/A"
        last_seen = conn.execute("SELECT MAX(captured_at) FROM flows").fetchone()[0]

        return Stats(
            total_flows=total,
            malicious_flows=malicious,
            avg_severity=round(avg_sev, 2),
            top_source=top_src,
            top_attackers=top_attackers,
            last_flow_timestamp=last_seen
        )
    finally:
        conn.close()

@app.get("/api/timeline", response_model=List[TimelinePoint])
def get_timeline(limit: int = 60):
    conn = get_db_connection()
    try:
        query = """
            SELECT substr(captured_at, 1, 16) AS minute_bucket,
                   COUNT(*) AS flow_count,
                   SUM(CASE WHEN verdict = 'malicious' THEN 1 ELSE 0 END) AS malicious_count
            FROM flows
            GROUP BY minute_bucket
            ORDER BY minute_bucket DESC
            LIMIT ?
        """
        rows = conn.execute(query, (limit,)).fetchall()
        # Reverse to show chronological order
        results = []
        for row in reversed(rows):
            results.append(TimelinePoint(
                bucket=row["minute_bucket"],
                flow_count=row["flow_count"],
                malicious_count=row["malicious_count"]
            ))
        return results
    finally:
        conn.close()

@app.get("/api/flows", response_model=List[Flow])
def get_flows(limit: int = 100, search: str = None, filters: str = None, min_id: int = None):
    conn = get_db_connection()
    try:
        query = """
            SELECT id, captured_at, src_ip, src_port, dst_ip, dst_port, protocol,
                   total_packets, flow_duration, verdict, 
                   ja4_pred, doh_pred, apt_pred,
                   confidence, severity, summary, features_json
            FROM flows
        """
        params = []
        where_clauses = []
        
        if min_id is not None:
            where_clauses.append("id > ?")
            params.append(min_id)
        
        if search:
            search_str = f"%{search}%"
            # Basic textual columns
            or_clauses = [
                "src_ip LIKE ?", 
                "dst_ip LIKE ?", 
                "verdict LIKE ?", 
                "severity LIKE ?"
            ]
            # Add parameters for the above 4
            params.extend([search_str, search_str, search_str, search_str])

            # Numeric columns cast to text for "contains" search
            or_clauses.append("CAST(src_port AS TEXT) LIKE ?")
            params.append(search_str)
            or_clauses.append("CAST(dst_port AS TEXT) LIKE ?")
            params.append(search_str)
            or_clauses.append("CAST(id AS TEXT) LIKE ?")
            params.append(search_str)

            where_clauses.append(f"({' OR '.join(or_clauses)})")
            
        if filters:
            try:
                filter_dict = json.loads(filters)
                main_cols = ["id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "verdict", 
                            "ja4_pred", "doh_pred", "apt_pred", 
                            "total_packets", "flow_duration", "severity"]
                
                for col, val in filter_dict.items():
                    if not val:
                        continue
                        
                    # Normalized value for easier searching
                    val_str = str(val)

                    if col in main_cols:
                        if "-" in val_str:
                            # Range: 100-200
                            try:
                                low, high = map(float, val_str.split("-"))
                                where_clauses.append(f"{col} BETWEEN ? AND ?")
                                params.extend([low, high])
                            except:
                                pass
                        else:
                            # Exact match logic (using LIKE for partial text match if desired, but sticking to logic)
                            # Actually, for standard inputs, partial match via LIKE is better for UX
                            if col in ["src_ip", "dst_ip", "verdict", "ja4_pred", "doh_pred", "apt_pred", "protocol", "severity"]:
                                where_clauses.append(f"{col} LIKE ?")
                                params.append(f"%{val_str}%")
                            else:
                                # Numeric exact
                                where_clauses.append(f"{col} = ?")
                                params.append(val_str)
                    else:
                        # Assume JSON feature
                        json_col = f"json_extract(features_json, '$.{col}')"
                        if "-" in val_str:
                             try:
                                low, high = map(float, val_str.split("-"))
                                where_clauses.append(f"{json_col} BETWEEN ? AND ?")
                                params.extend([low, high])
                             except:
                                pass
                        else:
                            where_clauses.append(f"{json_col} LIKE ?")
                            params.append(f"%{val_str}%")
            except Exception as e:
                print(f"Filter Error: {e}")
                pass

        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
            
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        
        rows = conn.execute(query, tuple(params)).fetchall()
        
        results = []
        for row in rows:
            flow_dict = dict(row)
            try:
                # specific safe parsing for features to get SNI
                feats = json.loads(flow_dict.get("features_json", "{}"))
                flow_dict["sni"] = feats.get("matched_sni_domain", None)
            except:
                flow_dict["sni"] = None
            results.append(Flow(**flow_dict))
            
        return results
    finally:
        conn.close()

@app.get("/api/flows/{flow_id}", response_model=FlowDetail)
def get_flow_detail(flow_id: int):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id, features_json FROM flows WHERE id = ?", (flow_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Flow not found")
        
        try:
            features = json.loads(row["features_json"])
        except:
            features = {}
            
        return FlowDetail(id=row["id"], features=features)
    finally:
        conn.close()

@app.get("/api/modules", response_model=ModuleStats)
def get_module_stats(limit: int = 1000):
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT id, src_ip, dst_ip, captured_at, verdict, ja4_pred, doh_pred, apt_pred, protocol, features_json FROM flows ORDER BY captured_at DESC LIMIT ?", (limit,)).fetchall()
        
        ja4_set = set()
        ja4s_set = set()
        ja4_io = Counter()
        ja4s_io = Counter()
        ja4h_io = Counter()
        ja4x_io = Counter()
        ja4ssh_io = Counter()
        ja4t_io = Counter()
        ja4ts_io = Counter()
        ja4l_io = Counter()
        ja4d_io = Counter()

        doh_data = []
        apt_data = []

        # DoH 2-Stage Counts
        doh_detected_count = 0
        doh_malicious_count = 0
        doh_benign_count = 0
        
        for row in rows:
            try:
                feats = json.loads(row["features_json"])
                
                # Helper to safely add to counter
                def add_metric(key, counter):
                    val = feats.get(key, "None")
                    if val != "None":
                        counter[val] += 1

                add_metric("ja4", ja4_io)
                if feats.get("ja4", "None") != "None": ja4_set.add(feats["ja4"])
                
                add_metric("ja4s", ja4s_io)
                if feats.get("ja4s", "None") != "None": ja4s_set.add(feats["ja4s"])

                add_metric("ja4h", ja4h_io)
                add_metric("ja4x", ja4x_io)
                add_metric("ja4ssh", ja4ssh_io)
                add_metric("ja4t", ja4t_io)
                add_metric("ja4ts", ja4ts_io)
                add_metric("ja4d", ja4d_io)
                
                # Combine JA4L Client and Server
                ja4l_c = feats.get("ja4l_c", "None")
                ja4l_s = feats.get("ja4l_s", "None")
                if ja4l_c != "None": ja4l_io[f"C:{ja4l_c}"] += 1
                if ja4l_s != "None": ja4l_io[f"S:{ja4l_s}"] += 1
                
                # DoH Logic (using updated metadata)
                is_known_doh = feats.get("is_known_doh_server", 0) == 1
                sni_match = feats.get("matched_sni_domain", "None") != "None"
                # Check for the explicit AI flag (robust check for boolean or string)
                s1_val = feats.get("stage1_doh", False)
                stage1_detected = (s1_val is True) or (str(s1_val).lower() == "true")
                
                # Plot Data
                if stage1_detected or is_known_doh or sni_match:
                    doh_data.append({
                        "response_time": feats.get("response_time_mean", 0),
                        "throughput": feats.get("flow_bytes_s", 0),
                        "is_doh": True
                    })
                
                # 2-Stage Model Stats (Simulation based on heuristics)
                # Stage 1: Detection
                if stage1_detected or is_known_doh or sni_match:
                    doh_detected_count += 1
                    # Stage 2: Classification (using specific module verdict)
                    if row["doh_pred"] == "malicious":
                        doh_malicious_count += 1
                    else:
                        doh_benign_count += 1

                # APT (All flows for scatter plot)
                apt_data.append({
                    "duration": feats.get("flow_duration", 0),
                    "packets": feats.get("total_packets", 0),
                    "verdict": row["verdict"]
                })
            except:
                pass
                
        def get_top(counter):
            return [{"hash": k, "count": v} for k, v in counter.most_common(20)]
        


        # Re-iterating slightly or just counting during the loop
        ja4_mal_count = 0
        ja4_ben_count = 0
        ja4_mal_flows = []
        doh_mal_flows = []
        
        # Initialize containers for recent feature flows
        recent_features = {
            'ja4': [], 'ja4s': [], 'ja4h': [], 'ja4x': [], 
            'ja4ssh': [], 'ja4t': [], 'ja4ts': [], 'ja4l': [], 'ja4d': []
        }
        
        # Reset cursor for counting or reuse rows
        for row in rows:
            try:
                 feats = json.loads(row["features_json"])
                 
                 # JA4 Logic
                 if feats.get("ja4", "None") != "None" or feats.get("ja4s", "None") != "None":
                     # Use specific JA4 module verdict
                     if row["ja4_pred"] == "malicious":
                         ja4_mal_count += 1
                         ja4_mal_flows.append({
                             "id": row["id"],
                             "src_ip": row["src_ip"],
                             "dst_ip": row["dst_ip"],
                             "captured_at": row["captured_at"],
                             "verdict": row["verdict"],
                             "ja4": feats.get("ja4", "N/A"),
                             "protocol": row["protocol"],
                             "ja4_sni": feats.get("ja4_sni", "N/A"),
                             "sni": feats.get("matched_sni_domain", "N/A"),
                             "ja4_version": feats.get("ja4_version", "N/A"),
                             "ja4_alpn": feats.get("ja4_alpn", "N/A")
                         })
                     else:
                         ja4_ben_count += 1
                

                 # DoH Logic (reuse robust detection logic)
                 is_known_doh = feats.get("is_known_doh_server", 0) == 1
                 sni_match = feats.get("matched_sni_domain", "None") != "None"
                 s1_val = feats.get("stage1_doh", False)
                 stage1_detected = (s1_val is True) or (str(s1_val).lower() == "true")
                 
                 if (stage1_detected or is_known_doh or sni_match) and row["doh_pred"] == "malicious":
                     doh_mal_flows.append({
                         "id": row["id"],
                         "src_ip": row["src_ip"],
                         "dst_ip": row["dst_ip"],
                         "captured_at": row["captured_at"],
                         "verdict": "malicious",
                         "sni": feats.get("matched_sni_domain", "N/A if encrypted"),
                         "response_time": feats.get("response_time_mean", 0)
                     })

                 # Collect recent flows for each feature type (limit 20 per type)
                 # Keys must match tab IDs in frontend
                 for feature_type in ['ja4', 'ja4s', 'ja4h', 'ja4x', 'ja4ssh', 'ja4t', 'ja4ts', 'ja4l', 'ja4d']:
                     val = feats.get(feature_type, None)
                     # Handle extraction lists (JA4X, JA4SSH segments) or single values
                     has_val = False
                     display_val = "N/A"
                     
                     if isinstance(val, list) and len(val) > 0:
                         has_val = True
                         display_val = str(val[0]) # Show first
                     elif val and str(val) != "None":
                         has_val = True
                         display_val = str(val)
                         
                     if has_val:
                         if len(recent_features[feature_type]) < 20:
                             recent_features[feature_type].append({
                                 "id": row["id"],
                                 "captured_at": row["captured_at"],
                                 "src_ip": row["src_ip"],
                                 "dst_ip": row["dst_ip"],
                                 "sni": feats.get("matched_sni_domain", None) or feats.get("ja4_sni", "N/A"),
                                 "value": display_val
                             })

            except Exception as e:
                print(f"DEBUG ERROR: {e}", flush=True)
                pass

        # --- NEW: Chart Data ---
        
        # 1. Threat Status (Open vs Resolved)
        # We can check the flows table for this
        status_counts = conn.execute("""
            SELECT is_resolved, COUNT(*) 
            FROM flows 
            WHERE verdict = 'malicious'
            GROUP BY is_resolved
        """).fetchall()
        
        open_count = 0
        resolved_count = 0
        for row in status_counts:
            # is_resolved: 0 = Open, 1 = Resolved
            if row[0] == 1:
                resolved_count = row[1]
            else:
                open_count = row[1]
                
        threat_status = {"open": open_count, "resolved": resolved_count}
        
        # 2. Module Activity (Who is flagging threats?)
        # Query module_decisions
        mod_activity_rows = conn.execute("""
            SELECT module_name, COUNT(*) 
            FROM module_decisions 
            WHERE label = 'malicious' 
            GROUP BY module_name
        """).fetchall()
        
        module_activity = {"ja4": 0, "doh": 0, "apt": 0}
        for row in mod_activity_rows:
            name = row[0]
            count = row[1]
            if name == 'ja4-module': module_activity["ja4"] = count
            elif name == 'doh-module': module_activity["doh"] = count
            elif name == 'apt-module': module_activity["apt"] = count
            
        # 3. Explicitly fetch malicious active flows (bypassing the 1000 limit)
        # This fixes the issue where count > 0 but list is empty if threats are old
        ja4_mal_flows = []
        doh_mal_flows = []
        
        # JA4 Malicious Flows
        ja4_rows = conn.execute("""
            SELECT id, src_ip, dst_ip, captured_at, verdict, protocol, features_json 
            FROM flows 
            WHERE ja4_pred = 'malicious' 
            ORDER BY captured_at DESC 
            LIMIT 50
        """).fetchall()
        
        for row in ja4_rows:
            try:
                f = json.loads(row["features_json"])
                ja4_mal_flows.append({
                     "id": row["id"],
                     "src_ip": row["src_ip"],
                     "dst_ip": row["dst_ip"],
                     "captured_at": row["captured_at"],
                     "verdict": row["verdict"],
                     "ja4": f.get("ja4", "N/A"),
                     "protocol": row["protocol"],
                     "ja4_sni": f.get("ja4_sni", "N/A"),
                     "sni": f.get("matched_sni_domain", "N/A"),
                     "ja4_version": f.get("ja4_version", "N/A"),
                     "ja4_alpn": f.get("ja4_alpn", "N/A")
                })
            except: pass

        # DoH Malicious Flows
        doh_rows = conn.execute("""
            SELECT id, src_ip, dst_ip, captured_at, verdict, features_json 
            FROM flows 
            WHERE doh_pred = 'malicious' 
            ORDER BY captured_at DESC 
            LIMIT 50
        """).fetchall()

        for row in doh_rows:
            try:
                f = json.loads(row["features_json"])
                doh_mal_flows.append({
                     "id": row["id"],
                     "src_ip": row["src_ip"],
                     "dst_ip": row["dst_ip"],
                     "captured_at": row["captured_at"],
                     "verdict": "malicious",
                     "sni": f.get("matched_sni_domain", "N/A if encrypted"),
                     "response_time": f.get("response_time_mean", 0)
                })
            except: pass

        return ModuleStats(
            ja4_diversity=len(ja4_set),
            ja4s_diversity=len(ja4s_set),
            top_ja4=get_top(ja4_io),
            top_ja4s=get_top(ja4s_io),
            top_ja4h=get_top(ja4h_io),
            top_ja4x=get_top(ja4x_io),
            top_ja4ssh=get_top(ja4ssh_io),
            top_ja4t=get_top(ja4t_io),
            top_ja4ts=get_top(ja4ts_io),
            top_ja4l=get_top(ja4l_io),
            top_ja4d=get_top(ja4d_io),
            doh_stats=doh_data,
            doh_detection_stats={"detected": doh_detected_count, "non_doh": len(rows) - doh_detected_count},
            doh_classification_stats={"malicious": module_activity["doh"], "benign": doh_benign_count},
            ja4_malicious_count=module_activity["ja4"],
            ja4_benign_count=ja4_ben_count,
            ja4_malicious_flows=ja4_mal_flows,
            doh_malicious_flows=doh_mal_flows,
            apt_stats=apt_data,
            recent_features=recent_features,
            # Charts
            module_activity=module_activity,
            threat_status_distribution=threat_status
        )
    finally:
        conn.close()

@app.get("/api/forensics", response_model=ForensicsStats)
def get_forensics_stats(limit: int = 1000):
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT features_json, dst_port, src_ip FROM flows ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        
        flag_counts = Counter()
        payload_fwd = []
        payload_bwd = []
        port_counts = Counter()
        src_ip_counts = Counter()
        
        for row in rows:
            port_counts[str(row["dst_port"])] += 1
            src_ip_counts[row["src_ip"]] += 1
            try:
                feats = json.loads(row["features_json"])
                
                # Flags
                if feats.get("syn_flag_count", 0) > 0: flag_counts["SYN"] += 1
                if feats.get("fin_flag_count", 0) > 0: flag_counts["FIN"] += 1
                if feats.get("rst_flag_count", 0) > 0: flag_counts["RST"] += 1
                if feats.get("psh_flag_count", 0) > 0: flag_counts["PSH"] += 1
                if feats.get("ack_flag_count", 0) > 0: flag_counts["ACK"] += 1
                
                # Payloads
                payload_fwd.append(feats.get("fwd_payload_bytes", 0))
                payload_bwd.append(feats.get("bwd_payload_bytes", 0))
            except:
                pass
                
        return ForensicsStats(
            flag_counts=[{"flag": k, "count": v} for k, v in flag_counts.most_common()],
            payload_stats={"fwd": payload_fwd, "bwd": payload_bwd},
            top_ports=[{"port": k, "count": v} for k, v in port_counts.most_common(10)],
            top_source_ips=[{"ip": k, "count": v} for k, v in src_ip_counts.most_common(10)]
        )
    finally:
        conn.close()

# --- Database Migration Helper ---
def run_migrations():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(flows)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if "is_resolved" not in columns:
            print("Migrating database: Adding is_resolved column to flows table...")
            conn.execute("ALTER TABLE flows ADD COLUMN is_resolved INTEGER DEFAULT 0")
        
        if "resolution_note" not in columns:
            print("Migrating database: Adding resolution_note column to flows table...")
            conn.execute("ALTER TABLE flows ADD COLUMN resolution_note TEXT")
            
        conn.commit()
    except Exception as e:
        print(f"Migration warning: {e}")
    finally:
        conn.close()

# Run migrations on module import/startup
run_migrations()

# Initialize Detection Engine (global)
engine = DetectionEngine(model_dir="ml_models")


from models import ResolutionRequest

@app.post("/api/ingest")
def ingest_flow(data: FeatureIngestRequest):
    conn = get_db_connection()
    try:
        # 1. Reconstruct FeatureRecord from raw payload
        # Ensure payload has minimal required fields for record properties if missing
        payload = data.payload.copy()
        payload.update({
            "src_ip": data.src_ip,
            "dst_ip": data.dst_ip,
            "src_port": data.src_port,
            "dst_port": data.dst_port,
            "protocol": data.protocol,
            "total_packets": data.total_packets,
            "flow_duration": data.flow_duration
        })
        
        record = FeatureRecord(payload=payload)
        
        # 2. Run Detection
        processed_record, aggregate, results = engine.process(record)
        
        # 3. Prepare Data for DB (using the NEW verdicts)
        pred_map = {"ja4_pred": "none", "doh_pred": "none", "apt_pred": "none"}
        for res in results:
            if "ja4" in res.module.lower(): pred_map["ja4_pred"] = res.label
            elif "doh" in res.module.lower(): pred_map["doh_pred"] = res.label
            elif "apt" in res.module.lower(): pred_map["apt_pred"] = res.label

        features_json = json.dumps(payload) # Save the raw payload as features
        
        with conn:
            # Insert FLow
            cursor = conn.execute("""
                INSERT INTO flows (
                    captured_at, src_ip, dst_ip, src_port, dst_port, protocol,
                    total_packets, flow_duration, ja4, ja4s, ja4h,
                    ja4_pred, doh_pred, apt_pred,
                    verdict, confidence, severity, summary, features_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data.captured_at, data.src_ip, data.dst_ip, data.src_port, data.dst_port, data.protocol,
                data.total_packets, data.flow_duration, 
                payload.get("ja4", "None"), payload.get("ja4s", "None"), payload.get("ja4h", "None"),
                pred_map["ja4_pred"], pred_map["doh_pred"], pred_map["apt_pred"],
                aggregate.verdict, aggregate.confidence, aggregate.severity, 
                f"{data.src_ip}:{data.src_port} -> {data.dst_ip}:{data.dst_port}", 
                features_json
            ))
            flow_id = cursor.lastrowid
            
            # Insert Modules
            for res in results:
                conn.execute("""
                    INSERT INTO module_decisions (
                        flow_id, module_name, label, confidence, score, rationale
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (flow_id, res.module, res.label, res.confidence, res.score, res.rationale))
            
        return {"status": "ok", "flow_id": flow_id, "verdict": aggregate.verdict}
    except Exception as e:
        print(f"Ingest Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/api/events/{event_id}/resolve")
def resolve_event(event_id: str, request: ResolutionRequest):
    conn = get_db_connection()
    try:
        # Extract Flow ID from Event ID (evt_flow_123 -> 123)
        if event_id.startswith("evt_flow_"):
            flow_id = int(event_id.replace("evt_flow_", ""))
            conn.execute("UPDATE flows SET is_resolved = 1, resolution_note = ? WHERE id = ?", (request.note, flow_id))
            conn.commit()
            return {"status": "success", "message": "Event marked as resolved"}
        else:
            # Handle virtual events
            return {"status": "success", "message": "Event acknowledged (virtual)"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.get("/api/flows/{flow_id}/record")
def get_flow_details(flow_id: int):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Flow not found")
        
        # Convert row to dict
        flow = dict(row)
        # Parse features_json
        if flow.get("features_json"):
            try:
                flow["features"] = json.loads(flow["features_json"])
            except:
                flow["features"] = {}
        
        return flow
    except Exception as e:
        print(f"Error fetching flow {flow_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.get("/api/events", response_model=List[ActionableEvent])
def get_events(limit: int = 50, status: str = "all", module: Optional[str] = None, min_confidence: float = 0.0):
    """
    Synthesizes actionable events.
    status options: 'open', 'resolved', 'system', 'all'
    module options: 'ja4', 'doh', 'apt' (optional)
    min_confidence: 0.0 - 1.0 (optional)
    """
    conn = get_db_connection()
    events = []
    
    try:
        # 1. THREATS (Open/Resolved) - Only fetch if not asking for just system logs
        if status != "system":
            # We join with module_decisions to get the AUTHORITATIVE source of the malicious verdict.
            # We group by flow id to avoid duplicates if multiple modules flagged it (though we pick one)
            # REMOVED HARDCODED CONFIDENCE THRESHOLD to allow UI filter control
            rows = conn.execute("""
                SELECT f.id, f.captured_at, f.src_ip, f.dst_ip, f.features_json, f.confidence, f.protocol, f.is_resolved, f.resolution_note,
                       md.module_name, md.rationale
                FROM flows f
                LEFT JOIN module_decisions md ON f.id = md.flow_id AND md.label = 'malicious'
                WHERE f.verdict = 'malicious'
                GROUP BY f.id
                ORDER BY f.confidence DESC, f.id DESC LIMIT 100
            """).fetchall()
            
            for row in rows:
                try:
                    is_resolved = row["is_resolved"] == 1
                    # Filter based on status param
                    if status == "open" and is_resolved: continue
                    if status == "resolved" and not is_resolved: continue
                    
                    # Filter based on confidence param
                    row_conf = row["confidence"] if row["confidence"] is not None else 0.0
                    if row_conf < min_confidence: continue

                    feats = json.loads(row["features_json"])
                    ja4 = feats.get("ja4", "N/A")
                    
                    # Strict attribution based on module_decisions
                    db_module = row["module_name"] # 'ja4-module', 'doh-module', 'apt-module' or None
                    
                    if db_module == 'doh-module':
                        event_type = "DoH Tunneling Detected"
                        module_source = "doh"
                    elif db_module == 'ja4-module':
                        event_type = "Malicious JA4 Fingerprint Match"
                        module_source = "ja4"
                    elif db_module == 'apt-module':
                        event_type = "APT / C2 Beaconing Detected"
                        module_source = "apt"
                    else:
                        # Fallback if no module decision record found (e.g. legacy data)
                        # Revert to heuristic check but prioritize DoH signals strongly
                        if feats.get("is_known_doh_server") or feats.get("is_doh_ip") or (feats.get("doh_probability", 0) > 0.5):
                            event_type = "DoH Tunneling Detected"
                            module_source = "doh"
                        elif ja4 != "N/A" and "Time" not in ja4:
                             event_type = "Malicious JA4 Fingerprint Match"
                             module_source = "ja4"
                        else:
                            event_type = "High Confidence Malicious Flow"
                            module_source = "general"

                    # Filter based on module param
                    if module and module.lower() != module_source: continue

                    events.append(ActionableEvent(
                        id=f"evt_flow_{row['id']}",
                        timestamp=row["captured_at"],
                        severity="critical" if not is_resolved else "info",
                        category="threat",
                        module_source=module_source,
                        confidence=row["confidence"],
                        title=f"{event_type} from {row['src_ip']}",
                        message=f"{row['rationale'] or 'Detected high-confidence malicious traffic.'} Targeting {row['dst_ip']}.",
                        source_ip=row["src_ip"],
                        affected_asset=row["dst_ip"],
                        action_required=not is_resolved,
                        recommended_action="Isolate source IP immediately." if not is_resolved else "No actions required",
                        status="open" if not is_resolved else "resolved",
                        resolution_note=row["resolution_note"],
                        flow_id=row["id"]
                    ))
                except Exception as e:
                    # print(f"Event build error: {e}")
                    pass

        # 2. SYSTEM LOGS (Virtual)
        if status == "system" or status == "all":
            import datetime
            # Mock system logs
            base_time = datetime.datetime.now()
            
            logs = [
                {
                    "id": "sys_log_001",
                    "offset": 0,
                    "title": "DoH Model Update",
                    "msg": "AegisNet DoH heuristics model updated to v2.4.5.",
                    "severity": "info"
                },
                {
                    "id": "sys_log_002",
                    "offset": 5,
                    "title": "Interface Monitor",
                    "msg": "Capture interface eth0 is operating promiscuous mode.",
                    "severity": "info"
                },
                {
                    "id": "sys_log_003",
                    "offset": 15,
                    "title": "GC Routine",
                    "msg": "Garbage collection freed 45MB of flow memory.",
                    "severity": "low"
                }
            ]
            
            for log in logs:
                t = (base_time - datetime.timedelta(minutes=log["offset"])).isoformat()
                events.append(ActionableEvent(
                    id=log["id"],
                    timestamp=t,
                    severity=log["severity"],
                    category="system",
                    module_source="system",
                    confidence=None, # Explicitly no confidence for system logs
                    title=log["title"],
                    message=log["msg"],
                    source_ip="localhost",
                    action_required=False,
                    recommended_action="Monitor system health.",
                    status="system",
                    flow_id=None
                ))

    except Exception as e:
        print(f"Error generating events: {e}")
        pass
    finally:
        conn.close()
        
    events.sort(key=lambda x: (x.confidence if x.confidence is not None else 0, x.timestamp), reverse=True)
    return events[:limit]
