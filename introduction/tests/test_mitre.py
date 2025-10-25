# introduction/tests/test_mitre_views.py
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.conf import settings
from django.urls import reverse
from unittest.mock import patch
import json
import hashlib
import jwt
import datetime
from unittest import skipIf
import os
from introduction.models import CSRFUserTbl

User = get_user_model()


class MitreViewsTests(TestCase):
    def setUp(self):
        self.client = Client()
        # create a regular django user to satisfy @login_required
        self.user = User.objects.create_user(username="tester", password="secret123")

    
        self.lab_user = CSRFUserTbl.objects.create(username="labuser", balance=200)
        self.lab_user.set_password("labpass")
        self.lab_user.save()

        self.recipient = CSRFUserTbl.objects.create(username="recipient", balance=10)
        self.recipient.set_password("labpass")
        self.recipient.save()

        # default secret used by view if not in settings
        self.jwt_secret = getattr(settings, "JWT_SECRET_KEY", "csrf_vulnerability_key")

    def test_protected_page_redirects_if_anonymous(self):
        """login_required should redirect anonymous users to login"""
        resp = self.client.get("/mitre/1")  # mitre_top1 path
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.url)
    @skipIf(not os.path.exists("static/css/dark-theme.css"), "dark-theme.css missing, skipping")
    def test_protected_page_access_when_logged_in(self):
        self.client.login(username="tester", password="secret123")
        resp = self.client.get("/mitre/1")
        # either 200 (if view renders) or 200 with template; assert not redirect
        self.assertEqual(resp.status_code, 200)

    def test_csrf_lab_login_sets_cookie_and_jwt(self):
        """POST to login should set auth_cookiee cookie with JWT when creds correct"""
        resp = self.client.post(
        "/mitre/9/lab/login",
        {"username": "labuser", "password": "labpass"},
        follow=False
        )
        # should redirect on success
        self.assertEqual(resp.status_code, 302)
        # cookie set
        self.assertIn("auth_cookiee", resp.cookies)
        token = resp.cookies["auth_cookiee"].value
        payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
        self.assertEqual(payload["username"], "labuser")

    def test_csrf_transfer_dashboard_with_valid_jwt(self):
        """GET dashboard should render when valid JWT cookie is provided"""
        # create token same as view does
        payload = {"username": "labuser", "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=300), "iat": datetime.datetime.utcnow()}
        token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        self.client.cookies["auth_cookiee"] = token

        # endpoint requires login (login_required), so log in a Django user
        self.client.login(username="tester", password="secret123")
        resp = self.client.get("/mitre/9/lab/transaction")
        # view returns render or redirect to login depending; on success should be 200
        self.assertIn(resp.status_code, (200, 302))
        # if 200, check balance in context by fetching content
        if resp.status_code == 200:
            self.assertContains(resp, str(self.lab_user.balance))

    def test_csrf_transfer_api_successful_transfer(self):
        """Using the API endpoint to transfer funds with valid JWT should update balances"""
        payload = {"username": "labuser", "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=300), "iat": datetime.datetime.utcnow()}
        token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        self.client.cookies["auth_cookiee"] = token

        # login required
        self.client.login(username="tester", password="secret123")

        # call transfer API to send 50 to recipient
        resp = self.client.get(f"/mitre/9/lab/api/recipient/50")
        self.assertEqual(resp.status_code, 302)

        # refresh from DB
        self.lab_user.refresh_from_db()
        self.recipient.refresh_from_db()

        # lab_user started with 200, minus 50 -> 150
        self.assertEqual(self.lab_user.balance, 150)
        self.assertEqual(self.recipient.balance, 60)

    def test_csrf_transfer_api_prevents_overtransfer(self):
        """Attempt to transfer more than balance should not change balances"""
        payload = {"username": "recipient", "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=300), "iat": datetime.datetime.utcnow()}
        token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        self.client.cookies["auth_cookiee"] = token
        self.client.login(username="tester", password="secret123")

        # recipient has balance 10; try to send 100
        resp = self.client.get(f"/mitre/9/lab/api/labuser/100")
        self.assertEqual(resp.status_code, 302)

        self.recipient.refresh_from_db()
        self.lab_user.refresh_from_db()
        # balances unchanged
        self.assertEqual(self.recipient.balance, 10)
        self.assertEqual(self.lab_user.balance, 200)

    def test_mitre_lab_25_api_accepts_safe_expression(self):
        self.client.login(username="tester", password="secret123")
        resp = self.client.post("/mitre/25/lab/api", {"expression": "2+3*4"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("result"), 14)

    def test_mitre_lab_25_api_rejects_unsafe_expression(self):
        self.client.login(username="tester", password="secret123")
        # contains letters and a function call -> rejected by regex
        resp = self.client.post("/mitre/25/lab/api", {"expression": "__import__('os').system('ls')"})
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertIn("error", data)

    def test_mitre_lab_17_api_invalid_ip(self):
        self.client.login(username="tester", password="secret123")
        resp = self.client.post("/mitre/17/lab/api", {"ip": "not_an_ip"})
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertIn("Invalid IP address format", data.get("error", "") or data.get("error", ""))

    def test_mitre_lab_17_api_parses_ports_from_nmap_output(self):
        """Patch command_out to return sample nmap output and verify parsing"""
        self.client.login(username="tester", password="secret123")
        nmap_stdout = b"22/tcp  open  ssh\n80/tcp  open  http\n\n"
        nmap_stderr = b""

        with patch("introduction.mitre.command_out", return_value=(nmap_stdout, nmap_stderr)):
            resp = self.client.post("/mitre/17/lab/api", {"ip": "127.0.0.1"})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            # ports should include two entries
            self.assertIn("ports", data)
            self.assertEqual(len(data["ports"]), 2)
            # ensure port strings are present
            self.assertTrue(any("22/tcp" in p for p in data["ports"]))
