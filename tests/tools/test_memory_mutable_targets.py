from unittest.mock import patch

from tools.memory_tool import memory_mutation_target_allowed


def test_mutable_targets_absence_preserves_legacy_behavior():
    with patch("hermes_cli.config.load_config_readonly", return_value={"memory": {}}):
        assert memory_mutation_target_allowed("memory") is True
        assert memory_mutation_target_allowed("user") is True


def test_mutable_targets_can_make_user_profile_read_only():
    config = {"memory": {"mutable_targets": ["memory"]}}
    with patch("hermes_cli.config.load_config_readonly", return_value=config):
        assert memory_mutation_target_allowed("memory") is True
        assert memory_mutation_target_allowed("user") is False


def test_malformed_mutable_targets_fail_closed():
    for value in (None, "memory", [], [""], [123]):
        config = {"memory": {"mutable_targets": value}}
        with patch("hermes_cli.config.load_config_readonly", return_value=config):
            assert memory_mutation_target_allowed("memory") is False


def test_config_read_failure_fails_closed():
    with patch("hermes_cli.config.load_config_readonly", side_effect=OSError("unavailable")):
        assert memory_mutation_target_allowed("memory") is False
