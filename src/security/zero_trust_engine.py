from dataclasses import dataclass, field
from typing import Dict, Optional, List, Any
import time
import uuid


@dataclass
class DevicePosture:
    os_version: str
    antivirus_running: bool
    patch_level: str


@dataclass
class SecurityContext:
    device: DevicePosture
    user_behavior_score: float  # 0.0 (benign) .. 1.0 (malicious)
    location_risk: float  # 0.0 (trusted) .. 1.0 (high risk)


@dataclass
class User:
    user_id: str
    roles: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)


@dataclass
class Resource:
    resource_id: str
    owner: Optional[str] = None
    allowed_groups: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class Request:
    request_id: str
    user: User
    resource: Resource
    headers: Dict[str, str]
    context: SecurityContext


@dataclass
class VerificationResult:
    success: bool
    reasons: List[str]
    trust_score: float


@dataclass
class AuthStatus:
    session_id: str
    authenticated: bool
    last_verified: float
    reason: Optional[str] = None


class ZeroTrustEngine:
    """Lightweight zero-trust engine.

    Principles:
    - Never trust, always verify
    - Least privilege
    - Assume breach
    """

    def __init__(self):
        # session store for continuous authentication checks
        self._sessions: Dict[str, AuthStatus] = {}

    def _check_device_posture(self, device: DevicePosture) -> List[str]:
        issues: List[str] = []
        # simple heuristics: require antivirus and reasonably recent OS
        if not device.antivirus_running:
            issues.append("antivirus_missing")
        # example minimal OS versions (toy check: string compare)
        try:
            if device.os_version and device.os_version < "10":
                issues.append("os_outdated")
        except Exception:
            # if version is non-numeric, ignore strict check
            pass
        return issues

    def evaluate_trust_score(self, context: SecurityContext) -> float:
        """Return a trust score 0..100 (higher = more trusted).

        Score is computed from device posture, user behavior, and location risk.
        """
        score = 100.0
        # device posture
        issues = self._check_device_posture(context.device)
        if issues:
            score -= 40.0
        # user behavior (higher is worse)
        score -= context.user_behavior_score * 30.0
        # location risk (higher is worse)
        score -= context.location_risk * 30.0
        # clamp
        score = max(0.0, min(100.0, score))
        return score

    def enforce_micro_segmentation(self, resource: Resource, user: User) -> bool:
        """Allow access only if user is in an allowed group or is owner.

        This enforces resource-level segmentation and least privilege.
        """
        if resource.owner and user.user_id == resource.owner:
            return True
        # intersection of groups
        if any(g in resource.allowed_groups for g in user.groups):
            return True
        return False

    def continuous_authentication(self, session_id: str) -> AuthStatus:
        """Re-verify identity for a session. Returns AuthStatus.

        For demo purposes, we mark sessions older than 15 minutes as requiring reauth.
        """
        now = time.time()
        st = self._sessions.get(session_id)
        if st is None:
            st = AuthStatus(session_id=session_id, authenticated=False, last_verified=0.0, reason="no_session")
            self._sessions[session_id] = st
            return st
        # if more than 15 minutes elapsed, require re-auth
        if now - st.last_verified > 15 * 60:
            st.authenticated = False
            st.reason = "reauth_required"
        else:
            st.authenticated = True
            st.reason = None
        return st

    def verify_every_request(self, request: Request) -> VerificationResult:
        """Authenticate and authorize every request—no implicit trust.

        Steps:
        - continuous authentication check
        - evaluate trust score
        - enforce micro-segmentation
        """
        reasons: List[str] = []
        # authenticate via session token header
        session_id = request.headers.get("X-Session-Id") or request.headers.get("Authorization")
        if not session_id:
            reasons.append("missing_session_token")
            return VerificationResult(False, reasons, 0.0)
        auth = self.continuous_authentication(session_id)
        if not auth.authenticated:
            reasons.append(auth.reason or "not_authenticated")
            # attempt to mark verified now for future requests (simulate auth step)
            auth.authenticated = True
            auth.last_verified = time.time()
            self._sessions[session_id] = auth

        # device posture & trust
        score = self.evaluate_trust_score(request.context)
        if score < 50.0:
            reasons.append("low_trust_score")

        # enforce segmentation
        allowed = self.enforce_micro_segmentation(request.resource, request.user)
        if not allowed:
            reasons.append("micro_segmentation_deny")

        success = (len(reasons) == 0)
        return VerificationResult(success=success, reasons=reasons, trust_score=score)

    # helpers for tests / session management
    def create_session(self, authenticated: bool = True) -> str:
        sid = str(uuid.uuid4())
        self._sessions[sid] = AuthStatus(session_id=sid, authenticated=authenticated, last_verified=time.time())
        return sid


__all__ = ["ZeroTrustEngine", "DevicePosture", "SecurityContext", "User", "Resource", "Request", "VerificationResult", "AuthStatus"]
