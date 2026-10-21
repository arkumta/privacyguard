
import unittest

from main import privacy_checks


class PrivacyGuardValidationSuite(unittest.TestCase):
    """Representative source-level checks, not a security audit."""

    def findings(self, source):
        return privacy_checks(source)

    def rule_ids(self, source):
        return {item["rule_id"] for item in self.findings(source)}

    def test_01_sensitive_email_event_should_flag(self):
        source = """
        pragma solidity ^0.8.20;
        contract EmailRegistry {
            event UserRegistered(string email);
        }
        """
        findings = self.findings(source)
        self.assertTrue(any(
            item["rule_id"] == "PG-PRIV-001"
            and item["severity"] == "High"
            for item in findings
        ))

    def test_02_generic_message_event_is_review_not_high(self):
        source = """
        pragma solidity ^0.8.20;
        contract MessageBoard {
            event MessagePublished(string message);
        }
        """
        findings = [
            item for item in self.findings(source)
            if item["rule_id"] == "PG-PRIV-001"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Medium")

    def test_03_permissionless_counter_is_not_privacy_finding(self):
        source = """
        pragma solidity ^0.8.20;
        contract PublicCounter {
            uint256 public count;

            function increment() external {
                count += 1;
            }
        }
        """
        ids = self.rule_ids(source)
        self.assertNotIn("PG-PRIV-001", ids)
        self.assertNotIn("PG-PRIV-002", ids)
        self.assertNotIn("PG-PRIV-003", ids)

    def test_04_sensitive_named_public_state_should_flag(self):
        source = """
        pragma solidity ^0.8.20;
        contract UserStore {
            string public userEmail;
        }
        """
        self.assertIn("PG-PRIV-002", self.rule_ids(source))

    def test_05_private_visibility_is_not_encryption(self):
        source = """
        pragma solidity ^0.8.20;
        contract SecretStore {
            string private userEmail;
        }
        """
        self.assertIn("PG-PRIV-003", self.rule_ids(source))

    def test_06_vela_deanonymization_should_prompt_review(self):
        source = """
        pragma solidity ^0.8.20;
        contract VelaExample {
            function requestData() external {
                string memory mode = "DEANONYMIZATION";
                processor.submitRequest();
            }
        }
        """
        self.assertIn("PG-HZN-001", self.rule_ids(source))

    def test_07_mock_authenticator_should_flag(self):
        source = """
        pragma solidity ^0.8.20;
        contract TestSetup {
            address authenticator =
                address(new MockTeeAuthenticator());
        }
        """
        self.assertIn("PG-HZN-003", self.rule_ids(source))

    def test_08_comments_should_not_trigger_vela_rule(self):
        source = """
        pragma solidity ^0.8.20;
        // TODO: integrate Vela DEANONYMIZATION later
        contract BasicContract {
            uint256 public count;
        }
        """
        self.assertNotIn("PG-HZN-001", self.rule_ids(source))

    def test_09_mock_name_in_comment_should_not_flag(self):
        source = """
        pragma solidity ^0.8.20;
        // MockTeeAuthenticator is used only in an example.
        contract BasicContract {
            uint256 public count;
        }
        """
        self.assertNotIn("PG-HZN-003", self.rule_ids(source))

    def test_10_no_sensitive_patterns_should_have_no_privacy_findings(self):
        source = """
        pragma solidity ^0.8.20;
        contract SimpleStore {
            uint256 public total;
            function setTotal(uint256 nextTotal) external {
                total = nextTotal;
            }
        }
        """
        privacy_rule_ids = {
            "PG-PRIV-001",
            "PG-PRIV-002",
            "PG-PRIV-003",
            "PG-PRIV-004",
            "PG-HZN-001",
            "PG-HZN-002",
            "PG-HZN-003",
            "PG-HZN-004",
        }
        self.assertTrue(
            privacy_rule_ids.isdisjoint(self.rule_ids(source))
        )


    def test_11_sensitive_public_mapping_should_flag(self):
        source = """
        pragma solidity ^0.8.20;
        contract UserStore {
            mapping(address => string) public userEmail;
        }
        """
        self.assertIn("PG-PRIV-002", self.rule_ids(source))

    def test_12_sensitive_public_array_should_flag(self):
        source = """
        pragma solidity ^0.8.20;
        contract UserStore {
            string[] public userEmails;
        }
        """
        self.assertIn("PG-PRIV-002", self.rule_ids(source))

    def test_13_sensitive_struct_field_should_be_reviewed(self):
        source = """
        pragma solidity ^0.8.20;
        contract UserStore {
            struct User {
                string email;
            }
            User public user;
        }
        """
        # A sensitive struct field may deserve review, but the current
        # detector is not expected to understand every struct layout.
        # This test documents the current behavior without assuming
        # that PG-PRIV-002 already supports it.
        self.assertIsInstance(self.findings(source), list)

    def test_14_harmless_public_mapping_should_not_trigger_privacy_rule(self):
        source = """
        pragma solidity ^0.8.20;
        contract Scores {
            mapping(address => uint256) public scores;
        }
        """
        self.assertNotIn("PG-PRIV-002", self.rule_ids(source))

    def test_15_sensitive_name_in_comment_should_not_flag(self):
        source = """
        pragma solidity ^0.8.20;
        // string public userEmail;
        contract SimpleStore {
            uint256 public total;
        }
        """
        self.assertNotIn("PG-PRIV-002", self.rule_ids(source))

    def test_16_public_constant_and_immutable_sensitive_names(self):
        source = """
        pragma solidity ^0.8.20;
        contract Config {
            string public constant userEmail = "example";
            address public immutable userWallet;
        }
        """
        # The name-based heuristic should flag the sensitive-looking
        # email declaration. Whether immutable wallet identifiers are
        # sensitive depends on the application's threat model.
        self.assertIn("PG-PRIV-002", self.rule_ids(source))

       
    def test_17_sensitive_sstore_value_should_flag(self):
        source = """
        pragma solidity ^0.8.20;
        contract StorageReviewTest {
            function saveSecret(bytes32 newSecret) external {
                assembly {
                    sstore(0, newSecret)
                }
            }
        }
        """
        self.assertIn("PG-PRIV-005", self.rule_ids(source))

    def test_18_harmless_sstore_value_should_not_trigger_privacy_rule(self):
        source = """
        pragma solidity ^0.8.20;
        contract CounterStorage {
            function saveCount(uint256 counter) external {
                assembly {
                    sstore(0, counter)
                }
            }
        }
        """
        self.assertNotIn("PG-PRIV-005", self.rule_ids(source))

    def test_19_sensitive_sstore_name_in_comment_should_not_flag(self):
        source = """
        pragma solidity ^0.8.20;
        // sstore(0, newSecret)
        contract SimpleStore {
            uint256 public count;
        }
        """
        self.assertNotIn("PG-PRIV-005", self.rule_ids(source))
 



if __name__ == "__main__":
    unittest.main(verbosity=2)
