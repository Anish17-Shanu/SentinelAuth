from shared.models import PolicyDecision, SubjectContext


def evaluate_policy(subject: SubjectContext, resource: str, action: str, resource_owner_id: str | None = None) -> PolicyDecision:
    roles = set(subject.roles)
    scopes = set(subject.scopes)
    department = str(subject.attributes.get("department", ""))
    clearance = int(subject.attributes.get("clearance_level", 1))
    risk_level = str(subject.attributes.get("risk_level", "low"))

    if risk_level == "high" and "security_admin" not in roles:
        return PolicyDecision(allowed=False, reason="high-risk context requires privileged review")

    if "admin" in roles or "security_admin" in roles:
        return PolicyDecision(allowed=True, reason="administrative role allowed", obligations=["audit"])

    if resource == "user_profile" and action == "read":
        if "profile:read" in scopes and subject.subject_id == resource_owner_id:
            return PolicyDecision(allowed=True, reason="self-service profile access allowed")
        if "support" in roles and department in {"support", "security"} and clearance >= 3:
            return PolicyDecision(allowed=True, reason="support role with sufficient clearance")

    return PolicyDecision(allowed=False, reason="policy denied")
