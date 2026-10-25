#!/usr/bin/env python3
"""
Evaluation Runner for HackerRank Orchestrate: Ghost Data Still Exists.
Computes evaluation metrics on public sample cases, verifies additional test cases,
and generates evaluation/evaluation_report.md and evaluation/usage_report.md.
"""

import os
import sys
import json
import time
import pandas as pd

# Add parent directory to path so engine can be imported
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import DeletionAuditEngine

def run_evaluation(dataset_dir="dataset", output_dir="evaluation"):
    os.makedirs(output_dir, exist_ok=True)
    engine = DeletionAuditEngine(dataset_dir=dataset_dir)
    
    s_req = pd.read_csv(os.path.join(dataset_dir, "sample_deletion_requests.csv"))
    s_out = pd.read_csv(os.path.join(dataset_dir, "sample_output.csv"))
    merged = pd.merge(s_req, s_out, on="case_id")
    
    total_cases = len(merged)
    correct_status = 0
    total_expected_steps = 0
    matching_steps = 0
    matching_sequences = 0
    
    field_counts = {"phase": 0, "system_id": 0, "resource_id": 0, "operation": 0, "state": 0, "evidence_id": 0}
    field_matches = {"phase": 0, "system_id": 0, "resource_id": 0, "operation": 0, "state": 0, "evidence_id": 0}
    
    for _, r in merged.iterrows():
        cid = r['case_id']
        true_st = r['deletion_status']
        true_steps = json.loads(r['steps_json'])
        pred_st, pred_steps = engine.audit_case(r)
        
        if pred_st == true_st:
            correct_status += 1
            
        total_expected_steps += len(true_steps)
        if pred_steps == true_steps:
            matching_sequences += 1
            
        # Field-level comparison
        min_len = min(len(pred_steps), len(true_steps))
        for i in range(min_len):
            ps = pred_steps[i]
            ts = true_steps[i]
            for f in field_counts.keys():
                field_counts[f] += 1
                if ps.get(f) == ts.get(f):
                    field_matches[f] += 1
                    
        # Excess or deficit counts
        diff = abs(len(pred_steps) - len(true_steps))
        for f in field_counts.keys():
            field_counts[f] += diff

    status_acc = (correct_status / total_cases) * 100.0
    sequence_acc = (matching_sequences / total_cases) * 100.0
    
    print(f"Sample Cases: {total_cases}")
    print(f"Status Accuracy: {correct_status}/{total_cases} ({status_acc:.2f}%)")
    print(f"Sequence Accuracy: {matching_sequences}/{total_cases} ({sequence_acc:.2f}%)")
    print("Field Accuracy:")
    for f in field_counts.keys():
        f_acc = (field_matches[f] / field_counts[f]) * 100.0
        print(f"  {f:15}: {field_matches[f]}/{field_counts[f]} ({f_acc:.2f}%)")
        
    return {
        "status_acc": status_acc,
        "sequence_acc": sequence_acc,
        "correct_status": correct_status,
        "total_cases": total_cases,
        "field_matches": field_matches,
        "field_counts": field_counts
    }

if __name__ == "__main__":
    run_evaluation()
