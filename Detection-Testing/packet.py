import unittest
from unittest.mock import patch
from scapy.all import IP, TCP
from IDS_detection import process_packet

class TestPacketProcessing(unittest.TestCase):

    @patch("IDS_detection.detect_nmap_scan")
    @patch("IDS_detection.detect_dos_attack")
    def test_process_packet(self, mock_dos, mock_nmap):
        packet = IP(src="192.168.1.5") / TCP(dport=80)
        process_packet(packet)

        mock_nmap.assert_called_once()
        mock_dos.assert_called_once()

if __name__ == "__main__":
    unittest.main()
