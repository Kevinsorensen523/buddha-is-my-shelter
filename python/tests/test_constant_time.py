from securekit import constant_time_equal


def test_equal_strings_match():
    assert constant_time_equal("abc123", "abc123")


def test_different_strings_do_not_match():
    assert not constant_time_equal("abc123", "abc124")


def test_different_length_strings_do_not_match():
    assert not constant_time_equal("short", "muchlongerstring")
