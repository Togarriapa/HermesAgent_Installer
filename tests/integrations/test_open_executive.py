"""R0083: review Open Executive as a separate, policy-gated application."""
import unittest

from hermes_installer.components.open_executive import (
    OpenExecutiveAdapterError,
    require_open_executive_workflow,
    review_open_executive_source,
)


def pinned_tree() -> dict[str, bytes]:
    # Contract excerpts follow the selected upstream FastAPI and Pydantic
    # sources; fixtures are inert and never start the application or providers.
    return {
        "packages/core/pyproject.toml": (
            b'[project]\nname = "openexecutive"\nversion = "0.5.2"\n'
            b'requires-python = ">=3.11"\nlicense = {text = "Apache-2.0"}\n'
        ),
        "packages/core/openexecutive/api/models.py": (
            b"class ChatRequest(BaseModel):\n"
            b"    message: str = Field(..., min_length=1, max_length=32000)\n"
            b"    session_id: str | None = None\n"
        ),
        "packages/core/openexecutive/api/routes/chat.py": (
            b'@router.post("/chat")\n'
            b"async def chat_stream(body: ChatRequest, request: Request) -> StreamingResponse:\n"
            b"    return await _run_chat_turn(message=body.message)\n"
        ),
        "packages/core/openexecutive/config.py": (
            b'alias="ANTHROPIC_API_KEY"\n'
            b'alias="OPENROUTER_ENABLED"\n'
            b'alias="LOCAL_BASE_URL"\n'
        ),
    }


class OpenExecutiveAdapterTests(unittest.TestCase):
    def test_discovers_documented_chat_contract_but_denies_unenrolled_workflow(self):
        review = review_open_executive_source(pinned_tree())
        self.assertEqual("303d45eaa0b2323f2e9646d19bf35dbcc98c6d71", review.source_revision)
        self.assertEqual("0.5.2", review.package_version)
        self.assertEqual("/chat", review.chat_path)
        self.assertTrue(review.chat_streams)
        self.assertEqual(32000, review.chat_request_limit)
        self.assertTrue(review.separate_provider_configuration)
        self.assertFalse(review.workflow_available)
        self.assertTrue(any("Hermes policy-gateway" in reason for reason in review.blockers))
        with self.assertRaisesRegex(PermissionError, "provider"):
            require_open_executive_workflow(review)

    def test_refuses_unreviewed_api_shape(self):
        source = pinned_tree()
        source["packages/core/openexecutive/api/routes/chat.py"] = b'@router.post("/chat")\ndef chat(): pass'
        with self.assertRaisesRegex(OpenExecutiveAdapterError, "streaming chat API"):
            review_open_executive_source(source)

    def test_non_linux_arm64_target_remains_unavailable(self):
        review = review_open_executive_source(pinned_tree(), target="darwin/arm64")
        self.assertFalse(review.workflow_available)
        self.assertIn("outside the reviewed", review.blockers[0])


if __name__ == "__main__":
    unittest.main()
