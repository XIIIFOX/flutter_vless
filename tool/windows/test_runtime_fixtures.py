"""Fixture isolation checks run without Windows APIs or network access."""
import unittest
from unittest.mock import patch

import runtime_smoke as runtime


def question(name):
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return header + labels + b"\0\0\x01\0\x01"


class RuntimeFixtureTest(unittest.TestCase):
    def test_synthetic_dns_is_scoped_and_other_names_use_encrypted_relay(self):
        with patch.object(runtime, "REAL_DNS", True), \
                patch.object(runtime, "real_dns_response", return_value=b"relay") as relay:
            self.assertTrue(runtime.dns_response(question("controlled.invalid")).endswith(bytes([198, 51, 100, 7])))
            relay.assert_not_called()
            self.assertEqual(b"relay", runtime.dns_response(question("api.github.com")))
            relay.assert_called_once()

    def test_domain_controls_remain_explicit_before_external_traffic(self):
        for reverse in (False, True):
            rules = runtime.config(reverse, "203.0.113.1")["routing"]["rules"]
            self.assertEqual("external-direct", rules[-1]["outboundTag"])
            self.assertEqual("tcp,udp", rules[-1]["network"])
            self.assertEqual("proxy", rules[2]["outboundTag"])
            self.assertEqual(["full:2ip.ru", "full:2ip.io"] if reverse else ["full:myip.com"], rules[2]["domain"])

    def test_proxy_only_fixture_keeps_original_default_outbound(self):
        profile = runtime.config(False)
        self.assertEqual("proxy", profile["outbounds"][0]["tag"])
        self.assertFalse(any(outbound["tag"] == "external-direct" for outbound in profile["outbounds"]))
        with patch.object(runtime, "REAL_DNS", False), patch.object(runtime, "real_dns_response") as relay:
            self.assertTrue(runtime.dns_response(question("example.com")).endswith(bytes([198, 51, 100, 7])))
            relay.assert_not_called()

    def test_encrypted_relay_checks_certificate_endpoint_status_and_dns_reply(self):
        query = question("example.com")
        reply = b"\x12\x34\x81\x80" + bytes(8)
        with patch.object(runtime.http.client, "HTTPSConnection") as factory:
            response = factory.return_value.getresponse.return_value
            response.status = 200
            response.getheader.return_value = "application/dns-message"
            response.read.return_value = reply
            self.assertEqual(reply, runtime.real_dns_response(query))
            self.assertEqual("1.1.1.1", factory.call_args.args[0])
            self.assertTrue(factory.call_args.kwargs["context"].check_hostname)
            self.assertEqual(query, factory.return_value.request.call_args.kwargs["body"])
            response.status = 403
            with self.assertRaises(ValueError):
                runtime.real_dns_response(query)
            response.status = 200
            response.read.return_value = b"\0\0" + reply[2:]
            with self.assertRaises(ValueError):
                runtime.real_dns_response(query)


if __name__ == "__main__":
    unittest.main()
