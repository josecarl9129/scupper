"""Pure tests for the independent L44 observer; no network or device access."""
import unittest

from reboot_sessions import dump_receipt, receipt_state, resolve_ambiguous


class ReceiptTests(unittest.TestCase):
    def test_fresh_device_sequence(self):
        self.assertEqual(receipt_state(0, 0), "absent")
        self.assertEqual(receipt_state(7, 92), "absent")
        self.assertEqual(receipt_state(7, 148), "transport")
        for k in range(17):
            rx = 180 + 112 * k
            self.assertEqual(receipt_state(7, rx), "ambiguous" if k == 14 else "transport")
        self.assertEqual(180 + 112 * 14, 1748)
        self.assertEqual(receipt_state(0, 1748), "absent")
        self.assertEqual(receipt_state(7, 184), "ambiguous")

    def test_retry_requires_real_transport_in_same_epoch(self):
        for following, accepted in [((7, 1860), True), ((8, 1860), False),
                                    ((0, 1860), False), ((7, 92), False),
                                    ((7, 1748), False), ((7, 1840), False)]:
            pauses = []
            sample, result, rows = resolve_ambiguous((7, 1748), lambda: following, pauses.append)
            self.assertEqual(result, accepted)
            self.assertEqual(sample, following)
            self.assertEqual(len(rows), 4 if following in [(7, 1748), (7, 1840)] else 1)
            self.assertEqual(pauses, [0.05] * len(rows))
        samples = iter([(7, 1748)] * 3 + [(7, 1860)])
        _, accepted, rows = resolve_ambiguous((7, 1748), lambda: next(samples), lambda _: None)
        self.assertTrue(accepted)
        self.assertEqual(len(rows), 4)

    def test_handshake_and_rx_come_from_same_peer_dump_row(self):
        dump = "private public 1234 off\nother psk endpoint ips 9 1860 10 0\nclient psk endpoint ips 7 1748 12 0\n"
        self.assertEqual(dump_receipt(dump, "client"), (7, 1748))
        self.assertEqual(dump_receipt(dump, "missing"), (0, 0))
        self.assertEqual(dump_receipt("client malformed 7 1860", "client"), (0, 0))


if __name__ == "__main__":
    unittest.main()
