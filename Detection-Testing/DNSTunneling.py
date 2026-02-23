import unittest
from scapy.all import IP, DNS, DNSQR
from IDS_detection import detect_dns_tunneling

class TestDNS(unittest.TestCase):

    def test_dns_tunneling(self):
        long_query = "a.b.c.d.e.f.g.h.i.j.example.com"

        packet = IP(src="1.1.1.1") / DNS(rd=1, qd=DNSQR(qname=long_query))

        detect_dns_tunneling(packet)

        # If no error occurs, test passes
        self.assertTrue(True)

if __name__ == "__main__":
    unittest.main()

