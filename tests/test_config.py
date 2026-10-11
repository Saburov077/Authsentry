from src.config import is_whitelisted

def test_whitelist_exact_match():
    whitelist = ["127.0.0.1", "192.168.1.100"]
    assert is_whitelisted("127.0.0.1", whitelist) is True
    assert is_whitelisted("192.168.1.100", whitelist) is True
    assert is_whitelisted("192.168.1.101", whitelist) is False

def test_whitelist_cidr_subnet():
    whitelist = ["10.0.0.0/24", "172.16.0.0/16"]
    assert is_whitelisted("10.0.0.55", whitelist) is True
    assert is_whitelisted("10.0.1.1", whitelist) is False
    assert is_whitelisted("172.16.200.4", whitelist) is True

def test_whitelist_invalid_ip():
    whitelist = ["10.0.0.0/24"]
    assert is_whitelisted("invalid_ip_format", whitelist) is False