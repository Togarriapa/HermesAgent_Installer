import pytest
from hermes_installer.remote.config import RemoteConfigError,validate_hostname,validate_emails

def test_hostname_requires_explicit_valid_value():
 with pytest.raises(RemoteConfigError):validate_hostname("")
 assert validate_hostname("desk.example.net")=="desk.example.net"
 with pytest.raises(RemoteConfigError):validate_hostname("https://desk.example.net")

def test_allowlist_normalizes_and_requires_email():
 assert validate_emails([" Owner@Example.net ","owner@example.net"])==("owner@example.net",)
 with pytest.raises(RemoteConfigError):validate_emails([])
