from __future__ import annotations

import unittest

from hermes_installer.authority.functional_health_receipt_consumer import (
    RootFunctionalHealthCompletion,
    RootFunctionalHealthReceiptConsumer,
)
from hermes_installer.authority.types import AuthorityDenied


class FunctionalHealthReceiptConsumerContracts(unittest.TestCase):
    def test_lifecycle_completion_cannot_be_fabricated(self):
        with self.assertRaises(TypeError):
            RootFunctionalHealthCompletion(
                1, "a" * 32, "transaction:1", "enrollment:1", "profile:1",
                "process-generation:1", "b" * 64, "c" * 32, {"status": "passed"},
                "publication:1")

    def test_consumer_requires_one_composed_root_registry_authority_and_observer(self):
        with self.assertRaises(AuthorityDenied):
            RootFunctionalHealthReceiptConsumer.from_root_committed_health(
                object(), object(), object(), object(), object())


if __name__ == "__main__":
    unittest.main()
