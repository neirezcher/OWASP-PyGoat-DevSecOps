import os
import tempfile
import hashlib
import uuid
from django.test import TestCase

from introduction.utility import (
    ssrf_html_input_extractor,
    unique_id_generator,
    filter_blog,
    customHash,
)


class SSRFCodeConverterTests(TestCase):
    def setUp(self):
        # Create a temporary directory structure for writing files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.file_path = os.path.join(self.temp_dir.name, "main.py")
        # Monkey-patch __file__ location
        self.original_dirname = os.path.dirname
        os.path.dirname = lambda _: self.temp_dir.name

    def tearDown(self):
        os.path.dirname = self.original_dirname
        self.temp_dir.cleanup()


class SSRFHTMLExtractorTests(TestCase):
    def test_extracts_values_from_inputs(self):
        html = """
        <input type="text" value="user1">
        <input type="hidden" value="token123">
        """
        result = ssrf_html_input_extractor(html)
        self.assertEqual(result, ["user1", "token123"])

    def test_returns_empty_list_if_no_inputs(self):
        html = "<p>No input here</p>"
        result = ssrf_html_input_extractor(html)
        self.assertEqual(result, [])


class UniqueIdGeneratorTests(TestCase):
    def test_unique_id_generator_returns_unique_values(self):
        """unique_id_generator should return a unique identifier each time"""
        ids = [unique_id_generator() for _ in range(5)]
        # Ensure all are unique and not None
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(isinstance(i, str) for i in ids))


class FilterBlogTests(TestCase):
    def test_filter_blog_returns_input(self):
        code = "<script>alert('x')</script>"
        self.assertEqual(filter_blog(code), code)


class CustomHashTests(TestCase):
    def test_customHash_reverses_sha256(self):
        password = "mypassword"
        expected = hashlib.sha256(password.encode()).hexdigest()[::-1]
        self.assertEqual(customHash(password), expected)

    def test_customHash_is_deterministic(self):
        """Ensure same input always produces same hash"""
        p = "test123"
        self.assertEqual(customHash(p), customHash(p))
