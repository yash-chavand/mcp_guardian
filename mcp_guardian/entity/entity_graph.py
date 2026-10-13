"""
Entity Relationship Validation & Privacy Tokenizer for MCP Guardian V2 (Feature 5).
Tracks Session -> Customer Entity -> Account -> Authorized Destination graphs.
"""

import re
import base64
import hashlib
from typing import Dict, List, Set, Any, Tuple, Optional
from dataclasses import dataclass, field
from ..core.events import RiskReason


@dataclass
class CustomerEntity:
    entity_id: str
    tokenized_id: str
    account_ids: Set[str] = field(default_factory=set)
    authorized_emails: Set[str] = field(default_factory=set)
    authorized_domains: Set[str] = field(default_factory=set)
    authorized_phone_numbers: Set[str] = field(default_factory=set)
    first_seen: float = 0.0


class EntityRelationshipValidator:
    """
    Maintains active session entity bindings and validates that subsequent outbound actions
    strictly target authorized entities.
    """

    def __init__(self, salt: str = "guardian_v2_entity"):
        self.salt = salt
        # session_id -> CustomerEntity
        self.session_bindings: Dict[str, CustomerEntity] = {}

    def _tokenize(self, raw_value: str) -> str:
        if not raw_value:
            return "anon"
        return hashlib.sha256(f"{self.salt}:{raw_value.lower().strip()}".encode("utf-8")).hexdigest()[:16]

    def _extract_domain(self, target: str) -> str:
        target = target.strip().lower()
        if "@" in target:
            return target.split("@")[-1]
        return target

    def _detect_encoded_identity(self, text: str) -> Optional[str]:
        """Detect base64-encoded email strings in text."""
        b64_pattern = r'[A-Za-z0-9+/]{12,}={0,2}'
        matches = re.findall(b64_pattern, text)
        for m in matches:
            try:
                decoded = base64.b64decode(m).decode("utf-8", errors="ignore")
                if "@" in decoded and "." in decoded:
                    return decoded
            except Exception:
                pass
        return None

    def bind_entity_from_lookup(self, session_id: str, order_data: Dict[str, Any]):
        """Bind customer email, order ID, and account info to active session."""
        if not order_data:
            return

        email = str(order_data.get("email", "")).strip().lower()
        order_id = str(order_data.get("order_id", "")).strip()
        account_id = str(order_data.get("account_id", order_data.get("customer_id", ""))).strip()

        if not email and not order_id:
            return

        if session_id not in self.session_bindings:
            entity = CustomerEntity(
                entity_id=email or f"entity-{order_id}",
                tokenized_id=self._tokenize(email or order_id)
            )
            self.session_bindings[session_id] = entity
        else:
            entity = self.session_bindings[session_id]

        if email:
            entity.authorized_emails.add(email)
            entity.authorized_domains.add(self._extract_domain(email))
        if order_id:
            entity.account_ids.add(order_id)
        if account_id:
            entity.account_ids.add(account_id)

    def validate_destination(
        self,
        session_id: str,
        destination_target: str,
        arguments: Dict[str, Any] = None
    ) -> Tuple[float, Optional[RiskReason]]:
        """
        Validate destination target against authorized session entity.
        Returns: (entity_risk_score [0.0, 1.0], Optional[RiskReason])
        """
        if not destination_target:
            return 0.0, None

        target_clean = destination_target.strip().lower()
        target_domain = self._extract_domain(target_clean)

        # Check for encoded identity attempts in arguments
        if arguments:
            for k, v in arguments.items():
                if isinstance(v, str):
                    encoded = self._detect_encoded_identity(v)
                    if encoded and session_id in self.session_bindings:
                        bound = self.session_bindings[session_id]
                        if encoded.lower() not in bound.authorized_emails:
                            return 0.95, RiskReason(
                                type="encoded_identity_exfiltration",
                                severity="critical",
                                message=f"Detected base64-encoded unauthorized recipient '{encoded}' in argument '{k}'."
                            )

        if session_id not in self.session_bindings:
            # First interaction sending email before looking up customer
            return 0.20, None

        bound = self.session_bindings[session_id]

        # 1. Exact Email Match -> Safe
        if target_clean in bound.authorized_emails:
            return 0.0, None

        # 2. Domain Match -> Low Risk
        if target_domain in bound.authorized_domains:
            return 0.15, None

        # 3. Mismatch -> Critical Risk Entity Hijacking
        return 0.95, RiskReason(
            type="entity_relationship_mismatch",
            severity="critical",
            message=(
                f"Outbound recipient '{target_clean}' does not match the active session entity "
                f"(Authorized: {list(bound.authorized_emails)})."
            )
        )

    def reset_session(self, session_id: str):
        self.session_bindings.pop(session_id, None)
