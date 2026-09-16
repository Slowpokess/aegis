import hashlib
from uuid import UUID

from app.domain.research_planner import (
    ExpectedInformation,
    ResearchIntentProposal,
    ResearchIntentStatus,
    ResearchIntentType,
)
from app.storage.repositories import RepositorySet

_EXPECTED = {
    ResearchIntentType.DISCOVER_SERVICES: ExpectedInformation.SERVICES,
    ResearchIntentType.RESOLVE_HOST: ExpectedInformation.DNS_ADDRESSES,
    ResearchIntentType.INSPECT_TLS: ExpectedInformation.TLS_METADATA,
    ResearchIntentType.OBSERVE_HTTP: ExpectedInformation.HTTP_METADATA,
    ResearchIntentType.VERIFY_CANDIDATE_SIGNAL: ExpectedInformation.CANDIDATE_EVIDENCE,
}


def intent_semantic_key(session_id: UUID, proposal: ResearchIntentProposal) -> str:
    parts = (
        str(session_id),
        proposal.intent_type.value,
        str(proposal.subject_entity_id),
        str(proposal.target_entity_id or ""),
        ",".join(sorted(item.value for item in proposal.expected_information)),
    )
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


class PlannerValidator:
    def __init__(self, max_intents: int = 3) -> None:
        self.max_intents = max_intents

    def validate_decision(self, session_id: UUID, intents: tuple[ResearchIntentProposal, ...]) -> None:
        if len(intents) > self.max_intents:
            raise ValueError("planner decision exceeds intent count limit")
        if len({intent_semantic_key(session_id, item) for item in intents}) != len(intents):
            raise ValueError("planner decision contains duplicate intents")

    def validate_intent(
        self,
        repositories: RepositorySet,
        session_id: UUID,
        proposal: ResearchIntentProposal,
    ) -> str:
        research = repositories.research_sessions.get(session_id)
        if research is None:
            raise ValueError("research session does not exist")
        valid_entities = {research.target.asset_id}
        for name in (
            "system_assets",
            "system_services",
            "system_endpoints",
            "system_identities",
            "system_roles",
            "system_data_objects",
        ):
            valid_entities.update(
                item.id for item in getattr(repositories, name).list_by_session(session_id)
            )
        if proposal.subject_entity_id not in valid_entities:
            raise ValueError("intent subject does not belong to research session")
        if proposal.target_entity_id and proposal.target_entity_id not in valid_entities:
            raise ValueError("intent target does not belong to research session")
        if _EXPECTED[proposal.intent_type] not in proposal.expected_information:
            raise ValueError("expected information is incompatible with intent")
        self._validate_provenance(repositories, session_id, proposal)
        key = intent_semantic_key(session_id, proposal)
        observations = repositories.observations.list_by_session(session_id)
        known_sources = {
            str(item.normalized_data.get("source_type", "")) for item in observations
        }
        already_known = {
            ResearchIntentType.DISCOVER_SERVICES: "nmap" in known_sources,
            ResearchIntentType.RESOLVE_HOST: "dns" in known_sources,
            ResearchIntentType.INSPECT_TLS: "tls" in known_sources,
            ResearchIntentType.OBSERVE_HTTP: any(
                item.source.value == "HTTP" for item in observations
            ),
            ResearchIntentType.VERIFY_CANDIDATE_SIGNAL: False,
        }[proposal.intent_type]
        if already_known:
            raise ValueError("requested information is already known")
        if any(
            item.semantic_key == key and item.status is ResearchIntentStatus.SATISFIED
            for item in repositories.research_intents.list_by_session(session_id)
        ):
            raise ValueError("research intent is already satisfied")
        return key

    @staticmethod
    def _validate_provenance(
        repositories: RepositorySet,
        session_id: UUID,
        proposal: ResearchIntentProposal,
    ) -> None:
        observations = {item.id for item in repositories.observations.list_by_session(session_id)}
        evidence = {item.id for item in repositories.evidence.list_by_session(session_id)}
        snapshots = repositories.attack_graph_snapshots.list_by_session(session_id)
        signals = {
            signal.id
            for snapshot in snapshots
            for signal in repositories.candidate_signals.list_by_graph(snapshot.id)
        }
        if not set(proposal.supporting_observation_ids).issubset(observations):
            raise ValueError("supporting observation crosses research sessions")
        if not set(proposal.supporting_evidence_ids).issubset(evidence):
            raise ValueError("supporting evidence crosses research sessions")
        if not set(proposal.supporting_signal_ids).issubset(signals):
            raise ValueError("supporting signal crosses research sessions")
        gap_ids = {
            item.id for item in repositories.evidence_gaps.list_by_session(session_id)
        }
        if not set(proposal.evidence_gap_ids).issubset(gap_ids):
            raise ValueError("evidence gap crosses research sessions")
        if (
            proposal.intent_type is ResearchIntentType.VERIFY_CANDIDATE_SIGNAL
            and not proposal.supporting_signal_ids
        ):
            raise ValueError("candidate verification intent requires a supporting signal")
