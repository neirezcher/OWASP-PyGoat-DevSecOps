from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.http import JsonResponse
from unittest.mock import patch


class ViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="tester", password="secret")
        self.client.login(username="tester", password="secret")

    def test_ssrf_code_checker_invalid_code(self):
        resp = self.client.post(
            "/api/ssrf",
            {"ssrf_code": "invalid_code"}
        )
        self.assertEqual(resp.status_code, 400)
    def test_A7_discussion_success_pattern(self):
        code = "AF_session_id.objects.get(session_id=cookie).delete()"
        resp = self.client.post("/2021/discussion/A7/api", {"code": code})
        self.assertEqual(resp.status_code, 200)
        self.assertJSONEqual(resp.content, {"message": "success"})


    def test_A7_discussion_failure(self):
        code = "print('no deletion')"
        resp = self.client.post("/2021/discussion/A7/api", {"code": code})
        self.assertEqual(resp.status_code, 400)

    @patch("introduction.playground.A6.utility.check_vuln")
    def test_A6_discussion_api_success(self, mock_check_vuln):
        mock_check_vuln.return_value = [{"package": "requests", "version": "2.28.0"}]
        resp = self.client.get("/2021/discussion/A6/api")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("vulns", resp.json())


    def test_log_function_checker_missing_fields(self):
        resp = self.client.post("/2021/discussion/A9/api", {"log_code": ""})
        self.assertEqual(resp.status_code, 400)
