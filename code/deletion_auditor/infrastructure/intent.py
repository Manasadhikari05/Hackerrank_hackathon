"""Request-intent classification (does request_text authorise deletion?).

``RuleBasedIntentClassifier`` is multilingual and deterministic. Explicit refusals ("do not close
the account", "not asking for deletion") always win over deletion keywords, because a request for
access, correction, export or a marketing opt-out must be NOT_APPLICABLE.

``LLMIntentClassifier`` is an optional second opinion used only when the rules are not confident.
"""

from __future__ import annotations

import logging
import re

from ..domain.models import DeletionRequest, IntentDecision
from ..interfaces.ml import IntentClassifier, ModelClient

log = logging.getLogger(__name__)

DELETION_PATTERNS = [
    r"\bdelet(e|ed|ing|ion)\b",
    r"\berase[d]?\b|\berasure\b",
    r"\bremove (my|the|this|any|all|it|records|that)\b",
    r"\bclose (my|this|the) account\b|\baccount closed\b|\bclosed my account\b",
    r"\bclose\b.*\baccount\b.*\bpermanently\b|\bclose this account permanently\b",
    r"\bdeleting my account\b",
    # verification of an earlier deletion ("confirm the profile is gone", "already been removed")
    r"\b(been|was|were|fully) removed\b",
    r"\b(profile|account) (is|was) gone\b",
    r"\bcannot identify me\b",
    r"suppression|supprimer|effacer",  # fr
    r"eliminar|eliminación|borrar",  # es
    r"exclusão|excluir|apagar",  # pt
    r"löschen|löschung",  # de
    r"cancellare|cancellazione",  # it
    r"削除",  # ja
    r"삭제",  # ko
    r"删除|刪除",  # zh
    r"удал",  # ru
]
REFUSAL_PATTERNS = [
    r"not (asking|requesting) for (deletion|erasure)",
    r"not a request to (erase|delete)",
    r"(do not|don't|dont) (close|delete|remove|erase)",
    r"without removing",
    r"keep the account",
    r"leave the account active",
    r"leave my (profile|account)",
    r"continue using the service",
    r"still (need|want|use) (the|my|it)",
    r"marketing lists? only",
    r"\bstop the promotional emails\b",
]
NON_DELETION_TOPICS = [
    r"\bdownload\b.*\bportable\b",
    r"\bcopy of (the|my|last)\b",
    r"\bcorrect it\b|\bmisspelled\b|\bout of date\b|\breplace it\b",
    r"\breset(ting)? the login\b",
    r"\bwhat personal information\b",
]


ENGLISH_DELETION_VERB = re.compile(r"\b(delet\w*|eras\w*|remov\w*|clos(?:e|ed|ing)\b)")
NEGATOR = re.compile(r"\b(not|never|no need to|don't|dont|doesn't|didn't|won't|shouldn't)\b")
NON_ENGLISH_DELETION = re.compile(
    r"suppression|supprimer|effacer|eliminar|eliminación|borrar|exclusão|excluir|apagar|löschen|löschung|"
    r"cancellare|cancellazione|削除|삭제|删除|刪除|удал"
)


def all_deletion_mentions_negated(text: str) -> bool:
    """True when every English deletion verb is negated within its own clause ("I do not want my account
    deleted", "no need to erase my data") and no other-language deletion cue is present."""
    if NON_ENGLISH_DELETION.search(text):
        return False
    mentions = 0
    for clause in re.split(r"[.!?;:\n]+", text):
        for m in ENGLISH_DELETION_VERB.finditer(clause):
            mentions += 1
            window = " ".join(clause[: m.start()].split()[-6:])
            if not NEGATOR.search(window):
                return False
    return mentions > 0


class RuleBasedIntentClassifier(IntentClassifier):
    def classify(self, request: DeletionRequest) -> IntentDecision:
        text = request.request_text.lower()
        refusal = [p for p in REFUSAL_PATTERNS if re.search(p, text)]
        deletion = [p for p in DELETION_PATTERNS if re.search(p, text)]
        topic = [p for p in NON_DELETION_TOPICS if re.search(p, text)]
        if refusal:
            return IntentDecision(False, 0.95, f"explicit non-deletion phrase: {refusal[0]}", "rules")
        if deletion and all_deletion_mentions_negated(text):
            # Every deletion mention is negated: a refusal, not an authorisation. Medium confidence so an
            # enabled LLM fallback can still arbitrate unusual phrasing.
            return IntentDecision(False, 0.75, "every deletion mention is negated", "rules")
        if deletion:
            confidence = 0.6 if topic else 0.95
            return IntentDecision(True, confidence, f"deletion phrase: {deletion[0]}", "rules")
        if topic:
            return IntentDecision(False, 0.9, f"non-deletion topic: {topic[0]}", "rules")
        return IntentDecision(False, 0.5, "no deletion phrase found", "rules")


class LLMIntentClassifier(IntentClassifier):
    """Consults a model only when the rule-based decision is uncertain (confidence < threshold)."""

    PROMPT = (
        "Decide whether this customer message asks the company to delete/erase/close their account or "
        "personal data. Requests for access, export, correction, password help or marketing opt-out are NOT "
        'deletion requests. Answer JSON {"deletion": true|false, "reason": str}.\nMessage:\n'
    )

    def __init__(self, client: ModelClient, fallback: IntentClassifier, threshold: float = 0.8):
        self._client = client
        self._fallback = fallback
        self._threshold = threshold

    def classify(self, request: DeletionRequest) -> IntentDecision:
        base = self._fallback.classify(request)
        if base.confidence >= self._threshold:
            return base
        try:
            out = self._client.structured_generate(self.PROMPT + request.request_text)
            verdict = out.get("deletion")
            if isinstance(verdict, bool):
                return IntentDecision(verdict, 0.85, str(out.get("reason", ""))[:200], "llm")
        except (ValueError, RuntimeError) as exc:
            log.warning("LLM intent classification failed for %s: %s", request.case_id, exc)
        return base
