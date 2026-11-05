from ramzfort.vault.session_state import SessionState


def test_session_states_exist() -> None:
    assert SessionState.ACTIVE
    assert SessionState.LOCKED
    assert SessionState.CLOSED


def test_session_states_are_unique() -> None:
    assert len(SessionState) == 3


def test_session_states_are_distinct() -> None:
    states = {
        SessionState.ACTIVE,
        SessionState.LOCKED,
        SessionState.CLOSED,
    }

    assert len(states) == 3


def test_session_state_names() -> None:
    assert SessionState.ACTIVE.name == "ACTIVE"
    assert SessionState.LOCKED.name == "LOCKED"
    assert SessionState.CLOSED.name == "CLOSED"