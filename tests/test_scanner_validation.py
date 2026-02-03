import pytest

from scanner_engine import ScanValidationError, validate_nmap_target, validate_target


def test_validate_target_accepts_valid_domain():
    assert validate_target("example.com") == "example.com"


def test_validate_target_accepts_https_url():
    assert validate_target("https://example.com") == "https://example.com"


@pytest.mark.parametrize("target", ["", " ", "ht!tp://bad", "http://"])
def test_validate_target_rejects_invalid_targets(target):
    with pytest.raises(ScanValidationError):
        validate_target(target)


def test_validate_nmap_target_accepts_cidr():
    assert validate_nmap_target("192.168.1.0/24") == "192.168.1.0/24"


def test_validate_nmap_target_accepts_url_hostname():
    assert validate_nmap_target("https://example.com") == "example.com"


def test_validate_nmap_target_accepts_ip_range():
    assert validate_nmap_target("192.168.1.10-20") == "192.168.1.10-20"


@pytest.mark.parametrize("target", ["invalid target", "256.1.1.1", "192.168.1.20-10"])
def test_validate_nmap_target_rejects_invalid(target):
    with pytest.raises(ScanValidationError):
        validate_nmap_target(target)
