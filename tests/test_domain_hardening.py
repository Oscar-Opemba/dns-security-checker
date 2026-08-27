import json
import unittest
from unittest.mock import patch

import app


class Response:
    status = 200
    headers = {}
    def __init__(self, payload): self.payload = payload
    def read(self, _limit=-1): return self.payload
    def __enter__(self): return self
    def __exit__(self, *args): pass


class TestDnsDomainHardening(unittest.TestCase):
    def test_unknown_record_type_is_rejected(self):
        with self.assertRaises(ValueError): app.query('example.com', 'ANY')

    def test_malformed_answer_shape_is_rejected(self):
        with patch('app.open_no_redirect', return_value=Response(json.dumps({'Answer': {}}).encode())):
            with self.assertRaises(ValueError): app.query('example.com', 'A')


if __name__ == '__main__': unittest.main()
