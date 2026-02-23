import unittest
from unittest.mock import patch
from IDS_detection import block_ip, BLOCKED_IPS

class TestBlockingFunction(unittest.TestCase):

    @patch("IDS_detection.subprocess.run")
    def test_block_ip(self, mock_subprocess):
        BLOCKED_IPS.clear()

        block_ip("192.168.1.10")

        self.assertIn("192.168.1.10", BLOCKED_IPS)
        mock_subprocess.assert_called()

if __name__ == "__main__":
    unittest.main()
