
from core.status_list import get_or_create_default_list, allocate_index, is_revoked, set_revoked


def test_status_list_allocate_and_revoke_cycle():
    sl = get_or_create_default_list()
    idx = allocate_index(sl.id)

    assert is_revoked(sl.id, idx) is False
    set_revoked(sl.id, idx)
    assert is_revoked(sl.id, idx) is True


def test_status_list_bounds():
    sl = get_or_create_default_list()
    try:
        set_revoked(sl.id, -1)
        assert False, "Expected ValueError"
    except ValueError:
        pass
