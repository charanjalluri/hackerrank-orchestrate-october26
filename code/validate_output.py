#!/usr/bin/env python3
"""
Comprehensive Validation Script for Ghost Data Still Exists submission.
Validates output.csv against all challenge and AGENTS.md rules.
"""

import os
import sys
import json
import pandas as pd

def validate_submission(output_csv_path="output.csv", dataset_dir="dataset"):
    print("=" * 70)
    print("SUBMISSION INTEGRITY AND COMPLIANCE VALIDATOR")
    print("=" * 70)
    
    errors = []
    warnings = []
    
    # 1. File existence
    if not os.path.exists(output_csv_path):
        print(f"[FAIL] Output file does not exist: {output_csv_path}")
        return False
    print(f"[PASS] Output file exists at: {output_csv_path}")
    
    # 2. Schema and Row count
    df = pd.read_csv(output_csv_path)
    expected_cols = ["case_id", "deletion_status", "steps_json"]
    if list(df.columns) != expected_cols:
        errors.append(f"Columns mismatch: expected {expected_cols}, got {list(df.columns)}")
    else:
        print(f"[PASS] Columns match expected schema: {expected_cols}")
        
    expected_rows = 518
    if len(df) != expected_rows:
        errors.append(f"Row count mismatch: expected {expected_rows}, got {len(df)}")
    else:
        print(f"[PASS] Exact row count matches: {len(df)} rows")
        
    # 3. Unique case IDs & Order
    reqs_df = pd.read_csv(os.path.join(dataset_dir, "deletion_requests.csv"))
    expected_case_ids = list(reqs_df['case_id'])
    # Numeric order
    expected_sorted = sorted(expected_case_ids, key=lambda x: int(x.split('_')[1]))
    
    actual_case_ids = list(df['case_id'])
    if len(actual_case_ids) != len(set(actual_case_ids)):
        errors.append("Duplicate case_ids found in output.csv")
    else:
        print("[PASS] All case_ids are unique.")
        
    if actual_case_ids != expected_sorted:
        errors.append("case_id ordering mismatch: rows must be sorted ascending by case_id")
    else:
        print("[PASS] Rows are correctly sorted ascending by case_id.")
        
    # 4. Allowed values & JSON parsing
    allowed_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    allowed_phases = {"FINDING", "REMEDIATION", "VERIFICATION"}
    allowed_ops = {
        "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
        "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
        "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"
    }
    allowed_states = {"PRESENT", "ABSENT", "REDACTED", "ANONYMIZED", "ACTIVE", "DISABLED", "BLOCKED"}
    
    ef = pd.read_csv(os.path.join(dataset_dir, "evidence_files.csv")).set_index("file_id")
    req_meta = reqs_df.set_index("case_id")
    
    phase_order_map = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    op_order_map = {
        "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
        "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
        "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2, "VERIFY_RECORD_ANONYMIZED": 3,
        "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5
    }

    status_counts = {}
    total_steps = 0
    
    for idx, row in df.iterrows():
        cid = row['case_id']
        st = row['deletion_status']
        steps_raw = row['steps_json']
        status_counts[st] = status_counts.get(st, 0) + 1
        
        if st not in allowed_statuses:
            errors.append(f"{cid}: Invalid deletion_status: {st}")
            
        try:
            steps = json.loads(steps_raw)
        except Exception as e:
            errors.append(f"{cid}: Failed to parse steps_json: {e}")
            continue
            
        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json is not an array")
            continue
            
        total_steps += len(steps)
        
        # NOT_APPLICABLE contract
        if st == "NOT_APPLICABLE":
            if steps != []:
                errors.append(f"{cid}: NOT_APPLICABLE must have steps_json=[] but had {len(steps)} steps")
            continue
            
        aud_at = req_meta.loc[cid, 'audit_at']
        
        # Check step numbering & consecutive
        for s_idx, s in enumerate(steps, 1):
            if not isinstance(s, dict):
                errors.append(f"{cid} Step {s_idx}: step is not a dict")
                continue
                
            step_no = s.get('step_no')
            if step_no != s_idx:
                errors.append(f"{cid} Step {s_idx}: step_no should be {s_idx}, got {step_no}")
                
            phase = s.get('phase')
            op = s.get('operation')
            state = s.get('state')
            ev_id = s.get('evidence_id', '')
            sys_id = s.get('system_id')
            res_id = s.get('resource_id')
            
            if phase not in allowed_phases:
                errors.append(f"{cid} Step {step_no}: Invalid phase: {phase}")
            if op not in allowed_ops:
                errors.append(f"{cid} Step {step_no}: Invalid operation: {op}")
            if state not in allowed_states:
                errors.append(f"{cid} Step {step_no}: Invalid state: {state}")
                
            # Evidence rules
            if phase == "FINDING":
                if not ev_id:
                    errors.append(f"{cid} Step {step_no}: FINDING step must have non-empty evidence_id")
                elif ev_id not in ef.index:
                    errors.append(f"{cid} Step {step_no}: FINDING evidence_id '{ev_id}' not found in manifest")
                else:
                    cap_at = ef.loc[ev_id, 'captured_at']
                    if cap_at > aud_at:
                        errors.append(f"{cid} Step {step_no}: Temporal violation! Evidence {ev_id} captured_at ({cap_at}) > audit_at ({aud_at})")
            elif phase == "REMEDIATION":
                if ev_id != "":
                    errors.append(f"{cid} Step {step_no}: REMEDIATION step must have empty evidence_id, got '{ev_id}'")
            elif phase == "VERIFICATION":
                if st == "COMPLETE":
                    if not ev_id:
                        errors.append(f"{cid} Step {step_no}: COMPLETE VERIFICATION step must have non-empty evidence_id")
                    elif ev_id not in ef.index:
                        errors.append(f"{cid} Step {step_no}: COMPLETE evidence_id '{ev_id}' not in manifest")
                    else:
                        cap_at = ef.loc[ev_id, 'captured_at']
                        if cap_at > aud_at:
                            errors.append(f"{cid} Step {step_no}: Temporal violation! COMPLETE verification evidence {ev_id} captured_at ({cap_at}) > audit_at ({aud_at})")
                elif st == "INCOMPLETE":
                    if ev_id != "":
                        errors.append(f"{cid} Step {step_no}: INCOMPLETE future VERIFICATION step must have empty evidence_id, got '{ev_id}'")

        # Step ordering validation
        def key_fn(s):
            return (
                phase_order_map.get(s.get("phase"), 99),
                op_order_map.get(s.get("operation"), 99),
                s.get("system_id", ""),
                s.get("resource_id", "")
            )
        sorted_steps = sorted(steps, key=key_fn)
        # Compare order ignoring step_no differences
        order_match = True
        for a, b in zip(steps, sorted_steps):
            if (a.get("phase"), a.get("operation"), a.get("system_id"), a.get("resource_id")) != \
               (b.get("phase"), b.get("operation"), b.get("system_id"), b.get("resource_id")):
                order_match = False
                break
        if not order_match:
            errors.append(f"{cid}: Steps are not sorted strictly by (phase, op, system_id, resource_id)")

    print(f"\n[SUMMARY] Evaluated {len(df)} cases, total {total_steps} steps.")
    print("Status Breakdown:")
    for k, v in status_counts.items():
        print(f"  {k:15}: {v:4d} ({v/len(df)*100:.1f}%)")
        
    if errors:
        print(f"\n[FAIL] Found {len(errors)} validation errors:")
        for e in errors[:20]:
            print(f"  - {e}")
        if len(errors) > 20:
            print(f"  ... and {len(errors)-20} more errors.")
        return False
    else:
        print("\n[SUCCESS] ALL VALIDATION CHECKS PASSED PERFECTLY WITH ZERO ERRORS!")
        return True

if __name__ == "__main__":
    success = validate_submission()
    sys.exit(0 if success else 1)
