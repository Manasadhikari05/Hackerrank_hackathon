"""Intent classification (rules + mocked LLM) and model-output guards. No network calls."""

import pytest

from deletion_auditor.infrastructure.intent import LLMIntentClassifier, RuleBasedIntentClassifier
from deletion_auditor.infrastructure.interpreters import LLMEvidenceInterpreter, RuleBasedInterpreter
from deletion_auditor.infrastructure.model_clients import ScriptedModelClient, parse_json_object
from tests.conftest import make_file, make_request

RULES = RuleBasedIntentClassifier()


@pytest.mark.parametrize(
    "text",
    [
        "Please delete my account and the personal data attached to it.",
        "Je demande la suppression définitive du compte associé à cette adresse e-mail.",
        "Solicito la eliminación permanente de la cuenta asociada a este correo.",
        "Solicito a exclusão permanente da conta associada a este e-mail.",
        "このメールアドレスに関連するアカウントの完全な削除を依頼します。",
        "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.",
        "Can you verify that my account was deleted?",
        "Please confirm that the profile is gone and that remaining records cannot identify me.",
        "I want to close this account permanently.",
    ],
)
def test_deletion_requests_are_authorised(text):
    assert RULES.classify(make_request(text=text)).authorizes_deletion


@pytest.mark.parametrize(
    "text",
    [
        "Please stop the promotional emails. I still need the account, so I am not asking for deletion.",
        "I'd like to download my account information in a portable format. Please keep the account as it is.",
        "My surname is misspelled on the account. Can you correct it without removing any of my records?",
        "Please remove me from marketing lists only. I still want receipts.",
        "Can you tell me what personal information you hold about me? This is an information request, not a request to erase it.",
        "I can't access my profile and need help resetting the login. Do not close the account.",
        "Please change the email address used for this account. I want to continue using the service.",
    ],
)
def test_non_deletion_requests_are_not_applicable(text):
    assert not RULES.classify(make_request(text=text)).authorizes_deletion


def test_llm_consulted_only_when_rules_uncertain():
    client = ScriptedModelClient(['{"deletion": true, "reason": "asks to wipe data"}'])
    clf = LLMIntentClassifier(client, RULES, threshold=0.8)
    assert clf.classify(make_request(text="Please delete my account.")).source == "rules"
    assert client.usage.calls == 0
    d = clf.classify(make_request(text="Wipe everything you have on me."))
    assert d.authorizes_deletion and d.source == "llm" and client.usage.calls == 1


def test_llm_failure_falls_back_to_rules():
    clf = LLMIntentClassifier(ScriptedModelClient(["not json"]), RULES)
    assert clf.classify(make_request(text="Wipe everything.")).source == "rules"


def test_llm_interpreter_drops_hallucinated_resource_ids():
    raw = "Screen shows profile for someone@example.com, reference analytics_55."
    reply = (
        '{"records": [{"resource_id": "analytics_55", "state": "PRESENT", "identifiers": ["someone@example.com"]},'
        ' {"resource_id": "account_999", "state": "PRESENT", "identifiers": ["invented@example.com"]}]}'
    )

    class NoRules(RuleBasedInterpreter):
        def interpret(self, raw_content, evidence):
            return []

    out = LLMEvidenceInterpreter(ScriptedModelClient([reply]), NoRules()).interpret(raw, make_file())
    assert [r.resource_id for r in out] == ["analytics_55"]
    assert "email:invented@example.com" not in out[0].identifiers


def test_parse_json_object_rejects_garbage():
    with pytest.raises(ValueError):
        parse_json_object("no braces")
    assert parse_json_object('text {"a": 1} tail') == {"a": 1}


@pytest.mark.parametrize("text", ["Can you look into my account?", "Something is wrong with my profile.", ""])
def test_ambiguous_wording_never_authorises_deletion(text):
    d = RULES.classify(make_request(text=text))
    assert not d.authorizes_deletion and d.confidence < 0.8  # low confidence -> LLM fallback if enabled
