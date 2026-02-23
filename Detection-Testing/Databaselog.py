import unittest
import sqlite3
import os
from IDS_detection import init_db, record_alert, DB_FILE

class TestDatabaseLogging(unittest.TestCase):

    def setUp(self):
        # Create fresh database
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        init_db()

    def test_record_alert(self):
        record_alert("Test Alert", "1.1.1.1", "Test message")

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts")
        rows = cursor.fetchall()
        conn.close()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1] is not None, True)

if __name__ == "__main__":
    unittest.main()
