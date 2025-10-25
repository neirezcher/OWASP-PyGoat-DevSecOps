from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from introduction.models import (
    FAANG, Info, Comments, Login, AuthLogin, CFUser,
    OTP, Tickits, SQLLabTable, Blogs, AFAdmin,
    AFSessionID, CSRFUserTbl
)
import time


User = get_user_model()


class TestFAANGModels(TestCase):
    def test_faang_and_info_relationship(self):
        company = FAANG.objects.create(company="Google")
        info = Info.objects.create(faang=company, ceo="Sundar Pichai", about="Search engine")
        self.assertEqual(str(company), "Google")
        self.assertEqual(info.faang.company, "Google")
        self.assertIn("Sundar", str(info))

    def test_comment_creation(self):
        comment = Comments.objects.create(name="Alice", comment="Hello World!")
        self.assertIn("Alice", str(comment))


class TestAuthAndPasswordHashing(TestCase):
    def test_login_password_hashing_and_check(self):
        l = Login.objects.create(user="testuser", password="plaintext")
        # should be hashed automatically
        self.assertTrue(l.password.startswith("pbkdf2_"))
        self.assertTrue(l.check_password("plaintext"))

    def test_authlogin_manual_set_password(self):
        u = AuthLogin(username="john", name="John Doe")
        u.set_password("secret123")
        u.save()
        self.assertTrue(u.password.startswith("pbkdf2_"))
        self.assertTrue(u.check_password("secret123"))

    def test_cfuser_double_password_fields(self):
        cf = CFUser(username="demo", password="pass1", password2="pass2")
        cf.save()
        self.assertTrue(cf.check_password("pass1"))
        self.assertTrue(cf.password.startswith("pbkdf2_"))
        self.assertTrue(cf.password2.startswith("pbkdf2_"))


class TestOTP(TestCase):
    def test_valid_otp_and_expiry(self):
        otp = OTP.objects.create(email="test@example.com", otp="123456")
        self.assertFalse(otp.is_expired())
        # simulate time passing
        otp.created_at = timezone.now() - timezone.timedelta(seconds=600)
        self.assertTrue(otp.is_expired(ttl_seconds=300))


class TestTickitsAndBlogs(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="tester", password="securepass")

    def test_tickits_creation(self):
        t = Tickits.objects.create(user=self.user, tickit="TK12345")
        self.assertIn(self.user.username, str(t))

    def test_blogs_creation(self):
        b = Blogs.objects.create(author=self.user, blog_id="B001")
        self.assertEqual(str(b), "B001")


class TestSQLLabTable(TestCase):
    def test_sql_lab_table_password_hashing(self):
        entry = SQLLabTable(id="row1", password="mypass")
        entry.save()
        self.assertTrue(entry.password.startswith("pbkdf2_"))
        self.assertTrue(entry.check_password("mypass"))


class TestAFAdminSession(TestCase):
    def test_admin_password_hash_and_check(self):
        admin = AFAdmin(username="admin", password="adminpass")
        admin.save()
        self.assertTrue(admin.password.startswith("pbkdf2_"))
        self.assertTrue(admin.check_password("adminpass"))

    def test_af_session_id_str(self):
        s = AFSessionID.objects.create(session_id="S123", user="demo")
        self.assertEqual(str(s), "demo")


class TestCSRFUserTbl(TestCase):
    def test_csrf_user_password_hashing(self):
        u = CSRFUserTbl(username="bob", password="123456", balance=500)
        u.save()
        self.assertTrue(u.password.startswith("pbkdf2_"))
        self.assertTrue(u.check_password("123456"))
        self.assertIn("bob", str(u))
