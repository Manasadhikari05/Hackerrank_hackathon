"""Optional live-model check, separate from the mocked suite. Never runs in CI by default.

Enable with:  AUDIT_LIVE_LLM=1 OPENAI_API_KEY=... python3 -m pytest code/tests -m live_llm
"""

import os

import pytest

from deletion_auditor.infrastructure.intent import LLMIntentClassifier, RuleBasedIntentClassifier
from tests.conftest import make_request

pytestmark = [
    pytest.mark.live_llm,
    pytest.mark.skipif(
        not (os.environ.get("AUDIT_LIVE_LLM") == "1" and os.environ.get("OPENAI_API_KEY")),
        reason="live LLM tests are opt-in",
    ),
]


def test_live_intent_classification_agrees_on_clear_cases():
    from deletion_auditor.infrastructure.model_clients import OpenAIModelClient

    client = OpenAIModelClient(os.environ.get("AUDIT_LLM_MODEL", "gpt-4o-mini"))
    clf = LLMIntentClassifier(client, RuleBasedIntentClassifier(), threshold=1.01)  # force the model path
    assert clf.classify(make_request(text="Please erase my account and all my data.")).authorizes_deletion
    assert not clf.classify(make_request(text="Send me a copy of my data; keep my account.")).authorizes_deletion
    assert client.usage.calls == 2
