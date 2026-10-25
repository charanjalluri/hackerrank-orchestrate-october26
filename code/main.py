#!/usr/bin/env python3
"""
HackerRank Orchestrate October 2026 — Ghost Data Still Exists
Entry point for the deletion-audit agent.

Generates root-level output.csv conforming to the challenge contract:
case_id,deletion_status,steps_json
"""

import os
import sys
import argparse
import time
import json
import pandas as pd
from engine import DeletionAuditEngine

def main():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists - Deletion Audit Pipeline")
    parser.add_argument("--dataset-dir", default="dataset", help="Path to dataset directory")
    parser.add_argument("--output-file", default="output.csv", help="Path to output CSV file")
    parser.add_argument("--validate-samples", action="store_true", help="Validate on sample requests first")
    args = parser.parse_args()

    start_time = time.time()
    print("=" * 70)
    print("HackerRank Orchestrate: Ghost Data Still Exists — Audit Engine")
    print("=" * 70)

    # 1. Initialize engine
    print(f"[*] Initializing DeletionAuditEngine with dataset: {args.dataset_dir}")
    init_start = time.time()
    engine = DeletionAuditEngine(dataset_dir=args.dataset_dir)
    init_time = time.time() - init_start
    print(f"[+] Engine initialized in {init_time:.2f}s. Indexed {len(engine.evidence_store.records)} evidence records.")

    # 2. Optional validation on samples
    if args.validate_samples:
        sample_req_path = os.path.join(args.dataset_dir, "sample_deletion_requests.csv")
        sample_out_path = os.path.join(args.dataset_dir, "sample_output.csv")
        if os.path.exists(sample_req_path) and os.path.exists(sample_out_path):
            print("\n[*] Validating against sample cases...")
            s_req = pd.read_csv(sample_req_path)
            s_out = pd.read_csv(sample_out_path)
            merged = pd.merge(s_req, s_out, on="case_id")
            status_correct = 0
            for _, r in merged.iterrows():
                pred_status, pred_steps = engine.audit_case(r)
                if pred_status == r['deletion_status']:
                    status_correct += 1
            print(f"[+] Sample status accuracy: {status_correct}/{len(merged)} ({status_correct/len(merged)*100:.1f}%)")

    # 3. Process evaluation requests
    eval_req_path = os.path.join(args.dataset_dir, "deletion_requests.csv")
    if not os.path.exists(eval_req_path):
        print(f"[!] Error: Deletion requests file not found: {eval_req_path}")
        sys.exit(1)

    print(f"\n[*] Loading evaluation requests from {eval_req_path}...")
    eval_reqs = pd.read_csv(eval_req_path)
    total_cases = len(eval_reqs)
    print(f"[*] Processing {total_cases} evaluation requests...")

    rows = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

    process_start = time.time()
    for idx, row in eval_reqs.iterrows():
        cid = row['case_id']
        status, steps = engine.audit_case(row)
        status_counts[status] = status_counts.get(status, 0) + 1
        
        # Ensure valid JSON string
        steps_str = json.dumps(steps, separators=(',', ':'))
        rows.append({
            "case_id": cid,
            "deletion_status": status,
            "steps_json": steps_str
        })
        
        if (idx + 1) % 100 == 0 or (idx + 1) == total_cases:
            print(f"    Processed {idx + 1}/{total_cases} requests...")

    process_time = time.time() - process_start
    print(f"[+] All {total_cases} requests processed in {process_time:.2f}s ({process_time/total_cases*1000:.1f} ms/req).")

    # 4. Sort strictly ascending by case_id
    out_df = pd.DataFrame(rows)
    # Natural/numeric sort on case_id: case_33 ... case_550
    out_df['cid_num'] = out_df['case_id'].apply(lambda x: int(x.split('_')[1]) if '_' in x else 0)
    out_df = out_df.sort_values('cid_num').drop(columns=['cid_num'])

    # 5. Write output.csv
    print(f"\n[*] Writing predictions to {args.output_file}...")
    out_df.to_csv(args.output_file, index=False, columns=["case_id", "deletion_status", "steps_json"])
    total_time = time.time() - start_time

    print(f"[+] Successfully wrote {len(out_df)} rows to {args.output_file}")
    print("\nDecision Summary:")
    for k, v in status_counts.items():
        print(f"  {k:15}: {v:4d} ({v/total_cases*100:.1f}%)")
    print(f"Total execution time: {total_time:.2f}s")
    print("=" * 70)

if __name__ == "__main__":
    main()
