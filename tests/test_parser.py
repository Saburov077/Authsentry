from src.parser import parse_auth_line

def test_parse_valid_failed_password():
    line = "Oct 11 00:15:10 ubuntu-server sshd[1042]: Failed password for root from 192.168.1.105 port 54822 ssh2"
    result = parse_auth_line(line)
    
    assert result is not None
    assert result["ip"] == "192.168.1.105"
    assert result["username"] == "root"
    assert result["time_str"] == "00:15:10"

def test_parse_invalid_user_failed_password():
    line = "Oct 11 00:15:12 ubuntu-server sshd[1045]: Failed password for invalid user admin from 10.0.0.15 port 54826 ssh2"
    result = parse_auth_line(line)
    
    assert result is not None
    assert result["ip"] == "10.0.0.15"
    assert result["username"] == "admin"

def test_parse_irrelevant_log_line():
    line = "Oct 11 00:15:11 ubuntu-server sshd[1043]: Accepted password for root from 192.168.1.50 port 54824 ssh2"
    result = parse_auth_line(line)
    
    assert result is None