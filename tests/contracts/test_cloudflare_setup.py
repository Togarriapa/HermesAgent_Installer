from __future__ import annotations
import json, time, unittest
from hermes_installer.network import BoundedNetwork, HTTPResult, NetworkError
from hermes_installer.remote.cloudflare import CloudflareClient, CloudflareError

def recorded_request(url, method, headers, body, socket_timeout, max_bytes):
    assert url.startswith("https://api.cloudflare.com/")
    assert headers["Authorization"] == "Bearer fixture-secret"
    return HTTPResult(200, {}, json.dumps({"success": True, "result": [
        {"id":"zone-a","name":"example.uk","status":"active","account":{"id":"account-a"}},
        {"id":"zone-b","name":"notexample.uk","status":"active","account":{"id":"account-b"}},
        {"id":"zone-c","name":"example.uk","status":"pending","account":{"id":"account-c"}}]}).encode())
def slow_request(*args):
    time.sleep(2)
    return HTTPResult(200, {}, b"{}")
def malformed_request(*args):
    return HTTPResult(200, {}, b"not-json")

class CloudflareClientTests(unittest.TestCase):
    def test_active_zone_suffix_boundary_and_account_scope(self):
        c=CloudflareClient("fixture-secret",network=BoundedNetwork(requester=recorded_request,deadline_seconds=1))
        zones=c.discover_zones("home.example.uk")
        self.assertEqual([(z.zone_id,z.account_id) for z in zones],[("zone-a","account-a")])
    def test_hard_deadline_cancels_slow_transport(self):
        c=CloudflareClient("fixture-secret",network=BoundedNetwork(requester=slow_request,deadline_seconds=.2,socket_timeout=.1))
        started=time.monotonic()
        with self.assertRaisesRegex(CloudflareError,"hard deadline"): c.request("GET","/zones")
        self.assertLess(time.monotonic()-started,1)
    def test_malformed_response_redacts_token(self):
        c=CloudflareClient("fixture-secret",network=BoundedNetwork(requester=malformed_request,deadline_seconds=1))
        with self.assertRaises(CloudflareError) as e: c.request("GET","/zones")
        self.assertNotIn("fixture-secret",str(e.exception))
        self.assertIn("invalid response",str(e.exception))
    def test_only_https_and_fixed_relative_paths(self):
        c=CloudflareClient("fixture-secret",network=BoundedNetwork(requester=recorded_request,deadline_seconds=1))
        with self.assertRaises(ValueError): c.request("GET","//attacker.example/path")
        with self.assertRaises(NetworkError): c.network.request("http://127.0.0.1/")
    def test_secret_is_header_not_url(self):
        c=CloudflareClient("fixture-secret",network=BoundedNetwork(requester=recorded_request,deadline_seconds=1))
        self.assertEqual(len(c.discover_zones("example.uk")),1)

if __name__ == "__main__": unittest.main()
