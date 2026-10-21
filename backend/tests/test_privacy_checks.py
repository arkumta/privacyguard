
import unittest

from main import privacy_checks


class PrivacyGuardRuleTests(unittest.TestCase):
    def rule_ids(self, source):
        return {finding["rule_id"] for finding in privacy_checks(source)}

    def test_sensitive_event_is_flagged(self):
        source = """
        pragma solidity ^0.8.20;
        contract Example {
            event UserData(string email);
        }
        """
        findings = privacy_checks(source)
        self.assertTrue(any(
            item["rule_id"] == "PG-PRIV-001"
            and item["severity"] == "High"
            for item in findings
        ))

    def test_dynamic_event_is_review_not_automatically_high(self):
        source = """
        pragma solidity ^0.8.20;
        contract Example {
            event MessagePublished(string message);
        }
        """
        findings = privacy_checks(source)
        event_findings = [
            item for item in findings
            if item["rule_id"] == "PG-PRIV-001"
        ]
        self.assertEqual(len(event_findings), 1)
        self.assertEqual(event_findings[0]["severity"], "Medium")

    def test_solidity_private_is_not_confidential(self):
        source = """
        pragma solidity ^0.8.20;
        contract Example {
            string private userEmail;
        }
        """
        self.assertIn("PG-PRIV-003", self.rule_ids(source))

    def test_vela_deanonymization_prompts_authorization_review(self):
        source = """
        pragma solidity ^0.8.20;
        contract Example {
            function requestData() external {
                string memory mode = "DEANONYMIZATION";
                processor.submitRequest();
            }
        }
        """
        self.assertIn("PG-HZN-001", self.rule_ids(source))

    def test_mock_authenticator_is_flagged(self):
        source = """
        pragma solidity ^0.8.20;
        contract Example {
            address authenticator =
                address(new MockTeeAuthenticator());
        }
        """
        self.assertIn("PG-HZN-003", self.rule_ids(source))


if __name__ == "__main__":
    unittest.main()
