import unittest
import tempfile
from IDS_detection import get_checksum

class TestHybridIDS(unittest.TestCase):

    def test_checksum(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"hello")
            tmp.close()

            result = get_checksum(tmp.name)
            self.assertIsNotNone(result)

if __name__ == "__main__":
    unittest.main()

