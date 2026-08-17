from app.services.administrators import SystemIdentity


def test_okapi_uses_linux_identity_and_final_english_menu(app, monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.administrators.current_system_identity",
        lambda: SystemIdentity("alice", "Alice Admin"),
    )
    runner = app.test_cli_runner()

    result = runner.invoke(args=["okapi", "--no-splash"], input="L\n")

    assert result.exit_code == 0
    assert "[ OKAPI ]\n\n\nWelcome, Alice Admin." in result.output
    for label in (
        "Pending incidents",
        "All incidents",
        "Incident details",
        "Approve remediation",
        "Reject remediation",
        "Remediation history",
        "Audit logs",
        "Rollback",
        "Dry-run mode",
        "System status",
        "Logout / Exit",
    ):
        assert label in result.output
    assert "Password" not in result.output
    assert "Create administrator" not in result.output
    assert "Account" not in result.output
