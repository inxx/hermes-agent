from agent.memory_manager import resolve_builtin_memory_flags


def test_missing_allowlist_preserves_legacy_global_flags():
    config = {"memory_enabled": True, "user_profile_enabled": True}

    assert resolve_builtin_memory_flags(config, "api_server") == (True, True)


def test_allowlist_enables_memory_only_for_listed_platform():
    config = {
        "memory_enabled": True,
        "user_profile_enabled": True,
        "enabled_platforms": ["discord"],
    }

    assert resolve_builtin_memory_flags(config, "discord") == (True, True)
    assert resolve_builtin_memory_flags(config, "api_server") == (False, False)


def test_allowlist_never_overrides_disabled_memory_flags():
    config = {
        "memory_enabled": False,
        "user_profile_enabled": True,
        "enabled_platforms": [" DISCORD "],
    }

    assert resolve_builtin_memory_flags(config, "Discord") == (False, True)


def test_malformed_or_empty_allowlist_fails_closed():
    base = {"memory_enabled": True, "user_profile_enabled": True}

    for value in (None, "discord", [], [""], [123]):
        config = {**base, "enabled_platforms": value}
        assert resolve_builtin_memory_flags(config, "discord") == (False, False)


def test_non_mapping_config_fails_closed():
    assert resolve_builtin_memory_flags(None, "discord") == (False, False)
