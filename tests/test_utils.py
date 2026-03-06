from vortex.utils import VERSION, setup_logging


def test_version_string():
    assert isinstance(VERSION, str)
    assert len(VERSION) > 0


def test_setup_logging_no_error():
    # Should not raise
    setup_logging(verbose=False)
    setup_logging(verbose=True)
