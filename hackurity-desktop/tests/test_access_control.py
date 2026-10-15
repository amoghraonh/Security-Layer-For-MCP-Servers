from pathlib import Path

from app.audit.approval_store import ApprovalStore
from app.auth.service import AuthStore
from app.security.access_control import AccessDecision, evaluate_protected_operation


def test_protected_operation_has_three_deterministic_outcomes() -> None:
    assert evaluate_protected_operation("list_resources", {}).decision is AccessDecision.ALLOW
    assert evaluate_protected_operation("restart_vm", {"resource_name": "dev-vm-01"}).decision is AccessDecision.REQUIRE_APPROVAL
    assert evaluate_protected_operation("delete_resource", {"resource_name": "prod-db"}).decision is AccessDecision.DENY


def test_approval_is_bound_to_arguments_and_consumed_once(tmp_path: Path) -> None:
    approvals = ApprovalStore(tmp_path / "audit.db")
    request = approvals.create("developer", "restart_vm", {"resource_name": "dev-vm-01"})
    assert approvals.decide(request["id"], "approver", True, "safe test")
    assert not approvals.consume(request["id"], "restart_vm", {"resource_name": "other-vm"})
    assert approvals.consume(request["id"], "restart_vm", {"resource_name": "dev-vm-01"})
    assert not approvals.consume(request["id"], "restart_vm", {"resource_name": "dev-vm-01"})


def test_auth_store_hashes_password_and_revokes_session(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.db")
    store.provision("admin", "very-long-local-test-password", "super_admin")
    token, identity = store.login("admin", "very-long-local-test-password") or ("", {})
    assert identity["role"] == "super_admin"
    assert store.current(token) == identity
    store.logout(token)
    assert store.current(token) is None
