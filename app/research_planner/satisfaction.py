from app.domain.observations import ObservationSource
from app.domain.research_planner import (
    IntentSatisfaction,
    ResearchIntent,
    ResearchIntentType,
)
from app.storage.repositories import RepositorySet


class IntentSatisfactionEvaluator:
    def evaluate(
        self, repositories: RepositorySet, intent: ResearchIntent
    ) -> IntentSatisfaction:
        observations = [
            item
            for item in repositories.observations.list_by_session(
                intent.research_session_id
            )
            if not intent.resulting_observation_ids
            or item.id in intent.resulting_observation_ids
        ]
        sources = {
            str(item.normalized_data.get("source_type", "")) for item in observations
        }
        if intent.intent_type is ResearchIntentType.DISCOVER_SERVICES:
            return (
                IntentSatisfaction.SATISFIED
                if "nmap" in sources
                else IntentSatisfaction.UNSATISFIED
            )
        if intent.intent_type is ResearchIntentType.RESOLVE_HOST:
            return IntentSatisfaction.SATISFIED if "dns" in sources else IntentSatisfaction.UNSATISFIED
        if intent.intent_type is ResearchIntentType.INSPECT_TLS:
            return IntentSatisfaction.SATISFIED if "tls" in sources else IntentSatisfaction.UNSATISFIED
        if intent.intent_type is ResearchIntentType.OBSERVE_HTTP:
            return (
                IntentSatisfaction.SATISFIED
                if any(item.source is ObservationSource.HTTP for item in observations)
                else IntentSatisfaction.UNSATISFIED
            )
        if observations:
            return IntentSatisfaction.ENOUGH_EVIDENCE_FOR_HYPOTHESIS
        return IntentSatisfaction.MORE_EVIDENCE_REQUIRED
