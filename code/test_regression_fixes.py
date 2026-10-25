import unittest
import pandas as pd
import json
import os
import sys

# Ensure repository root and code directory are on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from engine import DeletionAuditEngine, EvidenceStore

class TestRegressionFixes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = DeletionAuditEngine("dataset")
        cls.sample_reqs = pd.read_csv("dataset/sample_deletion_requests.csv")
        cls.sample_outs = pd.read_csv("dataset/sample_output.csv")

    def _get_case_data(self, case_id):
        req = self.sample_reqs[self.sample_reqs.case_id == case_id].iloc[0]
        out = self.sample_outs[self.sample_outs.case_id == case_id].iloc[0]
        return req, out

    def test_fix1_temporal_lower_bound(self):
        """FIX 1: Evidence captured before requested_at must not be matched.
        Regression test for case_07, case_08, and case_17."""
        # Case 07: evidence_46 (captured 2026-02-13) is before requested_at (2026-08-31)
        req07, _ = self._get_case_data("case_07")
        st07, steps07 = self.engine.audit_case(req07)
        cites07 = [s['evidence_id'] for s in steps07 if s['evidence_id']]
        self.assertNotIn("evidence_46", cites07, "case_07 must not cite pre-request evidence_46")
        self.assertIn("evidence_58", cites07, "case_07 must cite valid evidence_58")

        # Case 08: evidence_27 (captured 2026-05-29) is before requested_at (2026-08-29)
        req08, _ = self._get_case_data("case_08")
        st08, steps08 = self.engine.audit_case(req08)
        cites08 = [s['evidence_id'] for s in steps08 if s['evidence_id']]
        self.assertNotIn("evidence_27", cites08, "case_08 must not cite pre-request evidence_27")
        self.assertIn("evidence_59", cites08, "case_08 must cite valid evidence_59")

        # Case 17: evidence_67 and evidence_42 (captured 2026-03-10) are before requested_at (2026-08-19)
        req17, _ = self._get_case_data("case_17")
        st17, steps17 = self.engine.audit_case(req17)
        res_ids17 = [s['resource_id'] for s in steps17]
        self.assertNotIn("account_6523", res_ids17, "case_17 must not match stale account_6523 from March")
        self.assertNotIn("tombstone_17", res_ids17, "case_17 must not match stale tombstone_17 from March")
        self.assertIn("backup_3245", res_ids17, "case_17 must match backup_3245")

    def test_fix2_support_log_pii_redaction(self):
        """FIX 2: Support ticket is REDACTED only when ALL prohibited direct identifiers are null.
        Regression test for case_18 / evidence_94 where requester_email is exposed."""
        req18, _ = self._get_case_data("case_18")
        st18, steps18 = self.engine.audit_case(req18)
        
        # In evidence_94, support_5569 has exposed email mori.ren@gmail.com
        findings = [s for s in steps18 if s['phase'] == 'FINDING' and s['resource_id'] == 'support_5569']
        self.assertEqual(len(findings), 1, "support_5569 must be reported as a finding")
        self.assertEqual(findings[0]['operation'], "REPORT_EXPOSED_PII")
        self.assertEqual(findings[0]['state'], "PRESENT")
        self.assertEqual(findings[0]['evidence_id'], "evidence_94")

        remediations = [s for s in steps18 if s['phase'] == 'REMEDIATION' and s['resource_id'] == 'support_5569']
        self.assertEqual(len(remediations), 1)
        self.assertEqual(remediations[0]['operation'], "REDACT_RECORD")
        self.assertEqual(remediations[0]['state'], "REDACTED")

        verifications = [s for s in steps18 if s['phase'] == 'VERIFICATION' and s['resource_id'] == 'support_5569']
        self.assertEqual(len(verifications), 1)
        self.assertEqual(verifications[0]['operation'], "VERIFY_RECORD_REDACTED")
        self.assertEqual(verifications[0]['state'], "REDACTED")

    def test_fix3_recursive_nested_json_extraction(self):
        """FIX 3: Recursively extract scalar identifiers from nested JSON records.
        Regression test for case_16 / search_1007 and case_22 / search_8911."""
        # Case 16 -> search_1007 nested inside document dict
        req16, _ = self._get_case_data("case_16")
        st16, steps16 = self.engine.audit_case(req16)
        s1007_findings = [s for s in steps16 if s['phase'] == 'FINDING' and s['resource_id'] == 'search_1007']
        self.assertEqual(len(s1007_findings), 1, "search_1007 must be found via nested document extraction")
        self.assertEqual(s1007_findings[0]['operation'], "REPORT_REMAINING_RECORD")
        self.assertEqual(s1007_findings[0]['evidence_id'], "evidence_05")

        # Case 22 -> search_8911 nested inside document dict
        req22, _ = self._get_case_data("case_22")
        st22, steps22 = self.engine.audit_case(req22)
        s8911_findings = [s for s in steps22 if s['phase'] == 'FINDING' and s['resource_id'] == 'search_8911']
        self.assertEqual(len(s8911_findings), 1, "search_8911 must be found via nested document extraction")
        self.assertEqual(s8911_findings[0]['operation'], "REPORT_REMAINING_RECORD")
        self.assertEqual(s8911_findings[0]['evidence_id'], "evidence_05")

    def test_fix4_support_attachment_policy(self):
        """FIX 4: Respect SUPPORT_ATTACHMENT policy: REPORT_REMAINING_RECORD / DELETE_RECORD / VERIFY_RECORD_ABSENT.
        Regression test for case_13 / support_4218."""
        req13, _ = self._get_case_data("case_13")
        st13, steps13 = self.engine.audit_case(req13)

        finding = next((s for s in steps13 if s['phase'] == 'FINDING' and s['resource_id'] == 'support_4218'), None)
        self.assertIsNotNone(finding, "support_4218 must be a finding in case_13")
        self.assertEqual(finding['operation'], "REPORT_REMAINING_RECORD")
        self.assertEqual(finding['state'], "PRESENT")
        self.assertEqual(finding['evidence_id'], "evidence_03")

        remediation = next((s for s in steps13 if s['phase'] == 'REMEDIATION' and s['resource_id'] == 'support_4218'), None)
        self.assertIsNotNone(remediation)
        self.assertEqual(remediation['operation'], "DELETE_RECORD")
        self.assertEqual(remediation['state'], "ABSENT")

        verification = next((s for s in steps13 if s['phase'] == 'VERIFICATION' and s['resource_id'] == 'support_4218'), None)
        self.assertIsNotNone(verification)
        self.assertEqual(verification['operation'], "VERIFY_RECORD_ABSENT")
        self.assertEqual(verification['state'], "ABSENT")

    def test_fix5_anonymized_analytics_verification(self):
        """FIX 5: Associate anonymized analytics resource via deletion_worker execution batch evidence.
        Regression test for case_03, case_04, case_21, case_25, case_26, case_27, case_28."""
        expected_analytics = {
            "case_03": ("analytics_9406", "evidence_94"),
            "case_04": ("analytics_901", "evidence_56"),
            "case_21": ("analytics_5335", "evidence_92"),
            "case_25": ("analytics_1895", "evidence_92"),
            "case_26": ("analytics_4566", "evidence_92"),
            "case_27": ("analytics_4574", "evidence_92"),
            "case_28": ("analytics_6077", "evidence_92"),
        }

        for cid, (exp_res, exp_ev) in expected_analytics.items():
            req, _ = self._get_case_data(cid)
            st, steps = self.engine.audit_case(req)
            an_verif = [s for s in steps if s['phase'] == 'VERIFICATION' and s['system_id'] == 'analytics_platform']
            self.assertEqual(len(an_verif), 1, f"{cid} must have exactly one analytics verification step")
            self.assertEqual(an_verif[0]['resource_id'], exp_res, f"{cid} analytics resource mismatch")
            self.assertEqual(an_verif[0]['operation'], "VERIFY_RECORD_ANONYMIZED", f"{cid} operation mismatch")
            self.assertEqual(an_verif[0]['state'], "ANONYMIZED", f"{cid} state mismatch")
            self.assertEqual(an_verif[0]['evidence_id'], exp_ev, f"{cid} evidence citation mismatch")

    def test_fix6_unrelated_analytics_never_attached(self):
        """FIX 6: Prove that unrelated analytics events are never attached merely from global timestamp proximity.
        Regression test for case_01, case_09, case_13, case_14, case_16, case_17, case_19, case_20, case_23, case_24, case_31, case_32."""
        unrelated_cases = [
            "case_01", "case_09", "case_13", "case_14", "case_16", "case_17",
            "case_19", "case_20", "case_23", "case_24", "case_31", "case_32"
        ]
        for cid in unrelated_cases:
            req, _ = self._get_case_data(cid)
            st, steps = self.engine.audit_case(req)
            an_verifs = [s for s in steps if s['phase'] == 'VERIFICATION' and s['system_id'] == 'analytics_platform']
            self.assertEqual(len(an_verifs), 0, f"{cid} must NOT receive an analytics verification step from global proximity")
    def test_fix7_marketing_contact_classification(self):
        """FIX 7: Contact lookup / email_opt_in log in analytics_platform is classified as MARKETING_PROFILE.
        Regression test for case_12 / analytics_9914."""
        req12, out12 = self._get_case_data("case_12")
        st12, steps12 = self.engine.audit_case(req12)
        
        # Verify case_12 matches ground truth completely
        exp_steps12 = json.loads(out12['steps_json'])
        self.assertEqual(st12, out12['deletion_status'])
        self.assertEqual(steps12, exp_steps12, "case_12 steps must exactly match sample_output ground truth")
        
        # Specific step assertions
        finding = next((s for s in steps12 if s['phase'] == 'FINDING' and s['resource_id'] == 'analytics_9914'), None)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['operation'], "REPORT_REMAINING_RECORD")
        self.assertEqual(finding['state'], "PRESENT")
        self.assertEqual(finding['evidence_id'], "evidence_01")
        
        remediation = next((s for s in steps12 if s['phase'] == 'REMEDIATION' and s['resource_id'] == 'analytics_9914'), None)
        self.assertIsNotNone(remediation)
        self.assertEqual(remediation['operation'], "DELETE_RECORD")
        self.assertEqual(remediation['state'], "ABSENT")
        
        verification = next((s for s in steps12 if s['phase'] == 'VERIFICATION' and s['resource_id'] == 'analytics_9914'), None)
        self.assertIsNotNone(verification)
        self.assertEqual(verification['operation'], "VERIFY_RECORD_ABSENT")
        self.assertEqual(verification['state'], "ABSENT")

    def test_fix8_account_service_correlation(self):
        """FIX 8: Account service fallback correlation with forward pipeline lag and identity constraints.
        Regression test covering case_18, case_20, case_23, case_28, and case_31.
        Verifies:
        1. Correct account_service resources are selected for the 5 affected public cases.
        2. Candidate account deletion events strictly satisfy account_event_time <= reported_at.
        3. Accounts with conflicting identity in evidence are disqualified.
        4. Forward platform pipeline lag (account precedes downstream services) is respected."""
        expected_accounts = {
            "case_18": "account_5521",
            "case_20": "account_5037",
            "case_23": "account_410",
            "case_28": "account_5482",
            "case_31": "account_4857"
        }

        for cid, exp_acc in expected_accounts.items():
            req, _ = self._get_case_data(cid)
            st, steps = self.engine.audit_case(req)
            acc_steps = [s for s in steps if s['system_id'] == 'account_service']
            self.assertGreater(len(acc_steps), 0, f"{cid} must have an account_service step")
            sel_acc = acc_steps[0]['resource_id']
            self.assertEqual(sel_acc, exp_acc, f"{cid} account resource mismatch: expected {exp_acc}, got {sel_acc}")

            # General rule verification 1: account event must occur before or at reported_at
            rep_dt = pd.to_datetime(req['reported_at'])
            acc_events = self.engine.dw_acc[self.engine.dw_acc.resource_id == sel_acc]
            self.assertGreater(len(acc_events), 0, f"{sel_acc} must have a deletion event in dw_acc")
            acc_time = acc_events.iloc[0]['dt']
            self.assertLessEqual(acc_time, rep_dt, f"{sel_acc} event time {acc_time} must be <= reported_at {rep_dt}")

            # General rule verification 2: candidate cannot belong to another user in evidence
            uid, aliases = self.engine.resolver.resolve(req['email'])
            ev_idents = self.engine.acc_ev_idents.get(sel_acc, set())
            if len(ev_idents) > 0:
                self.assertTrue(any(a in ev_idents for a in aliases), f"{sel_acc} evidence identifiers must match current user aliases")

    def test_fix9_multiformat_log_ingestion(self):
        """FIX 9: Observability log ingestion must parse multi-format log lines:
        1. JSON-lines format
        2. Pipe-delimited format
        3. Syslog RFC5424 format
        4. Bracketed application trace format
        5. Cloud runtime export format

        Verifies:
        1. Direct parsing via EvidenceStore._parse_log_line for each format.
        2. Successful indexing of records from all 5 formats in EvidenceStore."""
        # 1. JSON Lines
        json_line = '{"service": "search_service", "trace_id": "tr-7722221", "resource_id": "search_9365", "result": "hit"}'
        res_json = EvidenceStore._parse_log_line(json_line)
        self.assertIsNotNone(res_json, "JSON line must be parsed")
        self.assertEqual(res_json.get('service'), 'search_service')
        self.assertEqual(res_json.get('trace_id'), 'tr-7722221')
        self.assertEqual(res_json.get('resource_id'), 'search_9365')

        # 2. Pipe-delimited
        pipe_line = '2026-02-03T05:57:51Z | DEBUG | account_service | tr-0668675 | profile_lookup_completed | instance="account-6" pod="account-c133" region="eu-central-1" resource_id="account_1334" rows="1" http_status="200" duration_ms="14" correlation_key="chao8287@fastmail.com"'
        res_pipe = EvidenceStore._parse_log_line(pipe_line)
        self.assertIsNotNone(res_pipe, "Pipe-delimited line must be parsed")
        self.assertEqual(res_pipe.get('service'), 'account_service')
        self.assertEqual(res_pipe.get('trace_id'), 'tr-0668675')
        self.assertEqual(res_pipe.get('resource_id'), 'account_1334')
        self.assertEqual(res_pipe.get('http_status'), '200')

        # 3. Syslog / RFC5424
        syslog_line = '2026-03-25T08:51:15Z <15>1 node-1 support_platform tr-7458912 - - level=DEBUG instance="support-4" resource_id="support_9464" requester_email="test@example.com"'
        res_syslog = EvidenceStore._parse_log_line(syslog_line)
        self.assertIsNotNone(res_syslog, "Syslog line must be parsed")
        self.assertEqual(res_syslog.get('service'), 'support_platform')
        self.assertEqual(res_syslog.get('trace_id'), 'tr-7458912')
        self.assertEqual(res_syslog.get('resource_id'), 'support_9464')

        # 4. Bracketed application trace
        bracket_line = '2026-02-22T10:58:45Z [DEBUG] [account_service] [tr-9071194] event: instance="account-5" resource_id="account_7023" http_status="200"'
        res_bracket = EvidenceStore._parse_log_line(bracket_line)
        self.assertIsNotNone(res_bracket, "Bracketed line must be parsed")
        self.assertEqual(res_bracket.get('service'), 'account_service')
        self.assertEqual(res_bracket.get('trace_id'), 'tr-9071194')
        self.assertEqual(res_bracket.get('resource_id'), 'account_7023')

        # 5. Cloud runtime export
        cloud_line = '2026-06-08T06:52:09Z requestId=tr-1108860 level=INFO function=search_service message="instance=\\"search-3\\" pod=\\"search-0696\\" region=\\"us-east-2\\" resource_id=\\"search_021\\" event=\\"index_query_completed\\" result=\\"hit\\""'
        res_cloud = EvidenceStore._parse_log_line(cloud_line)
        self.assertIsNotNone(res_cloud, "Cloud runtime line must be parsed")
        self.assertEqual(res_cloud.get('service'), 'search_service')
        self.assertEqual(res_cloud.get('trace_id'), 'tr-1108860')
        self.assertEqual(res_cloud.get('resource_id'), 'search_021')
        self.assertEqual(res_cloud.get('result'), 'hit')

        # Verify indexed evidence presence in EvidenceStore
        store_records = self.engine.evidence_store.records
        indexed_resources = {(r['file_id'], r['resource_id']) for r in store_records}

        self.assertIn(('evidence_34', 'search_9365'), indexed_resources, "JSON-lines evidence_34 record must be indexed")
        self.assertIn(('evidence_48', 'account_1334'), indexed_resources, "Pipe-delimited evidence_48 record must be indexed")
        self.assertIn(('evidence_39', 'support_9464'), indexed_resources, "Syslog evidence_39 record must be indexed")
        self.assertIn(('evidence_44', 'account_7023'), indexed_resources, "Bracketed evidence_44 record must be indexed")
        self.assertIn(('evidence_25', 'search_021'), indexed_resources, "Cloud runtime evidence_25 record must be indexed")

    def test_fix10_absent_account_direct_lookup(self):
        """FIX 10: Direct lookup of ABSENT account_service evidence for complete cases.
        Demonstrates that an ABSENT account record with empty identifiers (no PII)
        can be correctly selected by resource_id from EvidenceStore rather than falling
        back to an unrelated snapshot bundle.
        
        Regression coverage: case_21, case_25, case_26, case_27, case_28 citing evidence_92."""
        # 1. Verify existence of ABSENT account record with empty identifiers in EvidenceStore
        absent_acc_recs = [
            r for r in self.engine.evidence_store.records 
            if r['system_id'] == 'account_service' and r['resource_id'] == 'account_6440' and r['state'] == 'ABSENT'
        ]
        self.assertGreater(len(absent_acc_recs), 0, "ABSENT record for account_6440 must exist in EvidenceStore")
        ev92_rec = absent_acc_recs[0]
        self.assertEqual(ev92_rec['file_id'], 'evidence_92')
        self.assertEqual(len(ev92_rec['identifiers']), 0, "Record in evidence_92 legitimately contains no PII (empty identifiers)")

        # 2. Verify all 5 complete cases select evidence_92 and exactly match ground truth
        test_cases = {
            "case_21": "account_6440",
            "case_25": "account_3136",
            "case_26": "account_5684",
            "case_27": "account_3866",
            "case_28": "account_5482"
        }

        for cid, expected_acc in test_cases.items():
            req, exp_out = self._get_case_data(cid)
            st, steps = self.engine.audit_case(req)
            self.assertEqual(st, "COMPLETE", f"{cid} must be COMPLETE")
            
            # Find account verification step
            acc_verify = [s for s in steps if s['system_id'] == 'account_service' and s['operation'] == 'VERIFY_RECORD_ABSENT']
            self.assertEqual(len(acc_verify), 1, f"{cid} must contain exactly one account verification step")
            self.assertEqual(acc_verify[0]['resource_id'], expected_acc)
            self.assertEqual(acc_verify[0]['evidence_id'], 'evidence_92', f"{cid} must cite evidence_92 from direct lookup, not fallback snapshot")
            
            # Exact sequence match against sample_output.csv
            exp_steps = json.loads(exp_out.steps_json)
            self.assertEqual(steps, exp_steps, f"{cid} must exactly match ground truth sequence")

if __name__ == '__main__':
    unittest.main()


