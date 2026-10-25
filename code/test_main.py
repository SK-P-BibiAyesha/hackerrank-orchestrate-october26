import unittest
from datetime import datetime, timezone

import main


class RequestIntentTests(unittest.TestCase):
    def test_deletion_requests_in_multiple_languages(self):
        self.assertTrue(main.request_authorizes_deletion("Please delete my account."))
        self.assertTrue(main.request_authorizes_deletion("Solicito la eliminación de mi cuenta."))
        self.assertTrue(main.request_authorizes_deletion("このアカウントの削除をお願いします。"))

    def test_non_deletion_and_negated_requests_are_not_applicable(self):
        self.assertFalse(main.request_authorizes_deletion("Please export my data."))
        self.assertFalse(main.request_authorizes_deletion("Do not delete my account; correct my email."))
        self.assertFalse(main.request_authorizes_deletion("Unsubscribe me from marketing messages."))

    def test_deletion_follow_up_is_authorized(self):
        self.assertTrue(main.request_authorizes_deletion(
            "My deletion request failed; please inspect the systems."
        ))


class EvidenceStateTests(unittest.TestCase):
    def test_identity_resolution_includes_historical_email(self):
        by_email, fields = main.build_identity_index(
            [{"user_id": "user_1", "email": "current@example.test"}],
            [{
                "user_id": "user_1",
                "field_name": "email",
                "old_value": "old@example.test",
                "new_value": "current@example.test",
            }],
        )
        self.assertEqual(by_email["old@example.test"], {"user_1"})
        self.assertIn("old@example.test", fields["user_1"]["email"])

    def test_evidence_state_respects_tombstone_redaction(self):
        self.assertFalse(main.has_identifying_fields(
            {
                "subject_reference": "user_1",
                "name": None,
                "email": None,
                "phone": None,
                "email_hash": None,
            },
            {"user_id": {"user_1"}, "email": {"person@example.test"}},
            permit_stable_reference=True,
        ))

    def test_category_is_not_inferred_from_unrelated_field_values(self):
        self.assertEqual(
            main.category_for(
                "account_service",
                "customer_profiles",
                "",
                {
                    "resource_id": "account_1",
                    "signup_channel": "organic_search",
                },
            ),
            "USER_PROFILE",
        )

    def test_evidence_timestamp_is_timezone_aware(self):
        timestamp = main.parse_time("2026-09-15T12:00:00Z")
        self.assertEqual(timestamp.tzinfo, timezone.utc)

    def test_evidence_after_audit_cutoff_cannot_change_the_case(self):
        request = {
            "case_id": "case_cutoff",
            "email": "person@example.test",
            "request_text": "Please delete my account.",
            "audit_at": "2026-09-15T12:00:00Z",
        }
        captured_at = main.parse_time("2026-09-15T12:00:01Z")
        evidence = {
            "evidence_1": {"captured_at": captured_at},
        }
        observation = main.Observation(
            "evidence_1",
            captured_at,
            "account_service",
            "account_1",
            "USER_PROFILE",
            {"email": "person@example.test"},
        )
        result = main.audit_request(
            request,
            {"person@example.test": {"user_1"}},
            {"user_1": {"email": {"person@example.test"}}},
            {"USER_PROFILE": "DELETE"},
            evidence,
            [observation],
            {},
            {},
        )
        self.assertEqual(result["deletion_status"], "INCOMPLETE")
        self.assertEqual(result["steps"], [])

    def test_deletion_activity_links_resource_to_nearest_request(self):
        request = {
            "case_id": "case_1",
            "request_text": "Delete my account.",
            "reported_at": "2026-08-20T16:42:00Z",
        }
        activity = [
            {
                "event_type": "DELETE_RECORD",
                "event_time": "2026-08-20T16:41:43Z",
                "target_system": "account_service",
                "resource_id": "account_1",
            }
        ]
        self.assertEqual(
            main.activity_resources_by_request(activity, [request])["case_1"],
            {("account_service", "account_1")},
        )

    def test_snapshot_absence_verifies_a_temporally_linked_account(self):
        request = {
            "case_id": "case_1",
            "email": "person@example.test",
            "request_text": "Delete my account.",
            "requested_at": "2026-08-18T09:00:00Z",
            "reported_at": "2026-08-20T16:42:00Z",
            "audit_at": "2026-09-03T11:30:00Z",
        }
        evidence = {
            "evidence_1": {
                "captured_at": main.parse_time("2026-09-02T23:00:00Z"),
            }
        }
        activity = [
            {
                "event_type": "DELETE_RECORD",
                "event_time": "2026-08-20T16:41:43Z",
                "target_system": "account_service",
                "resource_id": "account_1",
            }
        ]
        result = main.audit_request(
            request,
            {"person@example.test": {"user_1"}},
            {"user_1": {"email": {"person@example.test"}}},
            {"USER_PROFILE": "DELETE"},
            evidence,
            [],
            {},
            {},
            activity_resources=main.activity_resources_by_request(
                activity, [request]
            ),
            snapshot_inventory={
                "evidence_1": {
                    ("account_service", "USER_PROFILE", "customer_profiles"): set(),
                }
            },
        )
        self.assertEqual(result["deletion_status"], "COMPLETE")
        self.assertEqual(result["steps"][0]["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(result["steps"][0]["resource_id"], "account_1")
        self.assertEqual(result["steps"][0]["evidence_id"], "evidence_1")

    def test_present_failover_replica_is_not_overridden_by_primary_absence(self):
        request = {
            "case_id": "case_1",
            "email": "person@example.test",
            "request_text": "Delete my account.",
            "requested_at": "2026-08-18T09:00:00Z",
            "reported_at": "2026-08-20T16:42:00Z",
            "audit_at": "2026-09-03T11:30:00Z",
        }
        evidence = {
            "evidence_primary": {
                "captured_at": main.parse_time("2026-09-02T23:00:00Z"),
            },
            "evidence_failover": {
                "captured_at": main.parse_time("2026-09-02T23:00:00Z"),
            },
        }
        activity = [
            {
                "event_type": "DELETE_RECORD",
                "event_time": "2026-08-20T16:41:43Z",
                "target_system": "account_service",
                "resource_id": "account_1",
            }
        ]
        observation = main.Observation(
            "evidence_failover",
            evidence["evidence_failover"]["captured_at"],
            "account_service",
            "account_1",
            "USER_PROFILE",
            {"email": "person@example.test"},
            "PRESENT",
            "customer_profiles_failover_replica",
        )
        result = main.audit_request(
            request,
            {"person@example.test": {"user_1"}},
            {"user_1": {"email": {"person@example.test"}}},
            {"USER_PROFILE": "DELETE"},
            evidence,
            [observation],
            {},
            {},
            activity_resources=main.activity_resources_by_request(
                activity, [request]
            ),
            snapshot_inventory={
                "evidence_primary": {
                    ("account_service", "USER_PROFILE", "customer_profiles"): set(),
                },
                "evidence_failover": {
                    (
                        "account_service",
                        "USER_PROFILE",
                        "customer_profiles_failover_replica",
                    ): {"account_1"},
                },
            },
        )
        self.assertEqual(result["deletion_status"], "INCOMPLETE")
        self.assertTrue(
            any(
                step["operation"] == "REPORT_REMAINING_RECORD"
                and step["evidence_id"] == "evidence_failover"
                for step in result["steps"]
            )
        )


if __name__ == "__main__":
    unittest.main()
