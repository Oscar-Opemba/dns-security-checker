import unittest
from unittest.mock import patch
from app import analyze

class TestDNS(unittest.TestCase):
    @patch('app.query', side_effect=lambda host, kind: ['sample'] if kind == 'TXT' else [])
    def test_dmarc_and_spf_are_separated(self, _query):
        result = analyze({'host': 'example.com'})
        self.assertIn('records', result)
        self.assertIn('dmarc_records', result)

if __name__ == '__main__': unittest.main()
