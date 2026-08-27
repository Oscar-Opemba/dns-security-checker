import unittest
from unittest.mock import patch
from app import analyze

class TestDNSEdgeCases(unittest.TestCase):
    @patch('app.query', return_value=[])
    def test_fixed_query_set_and_invalid_host(self, query):
        result = analyze({'host':'example.com'})
        self.assertEqual(result['queries_made'], 6)
        self.assertEqual(query.call_count, 6)
        self.assertIn('error', analyze({'host':'https://example.com'}))

if __name__ == '__main__': unittest.main()
