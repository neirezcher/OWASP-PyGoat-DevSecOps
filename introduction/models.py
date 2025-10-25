from django.conf import settings
from django.core.validators import MaxValueValidator, RegexValidator, MinLengthValidator
from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone


# ------------------------
# Production / shared models
# ------------------------
class FAANG(models.Model):
    id = models.AutoField(primary_key=True)
    company = models.CharField(max_length=200)

    class Meta:
        verbose_name = "FAANG Company"
        verbose_name_plural = "FAANG Companies"
        indexes = [models.Index(fields=["company"])]

    def __str__(self):
        return self.company


class Info(models.Model):
    id = models.AutoField(primary_key=True)
    faang = models.ForeignKey(
        FAANG, on_delete=models.CASCADE, related_name="infos"
    )
    ceo = models.CharField(max_length=200)
    about = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.faang.company} - {self.ceo}"


class Comments(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200)
    comment = models.CharField(max_length=600)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name}: {self.comment[:40]}"


# ------------------------
# Authentication/demo models
# ------------------------

class Login(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.CharField(max_length=200)
    # Store hashed password (not plaintext)
    password = models.CharField(max_length=128)

    def set_password(self, raw_password: str):
        self.password = make_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password(raw_password, self.password)

    def save(self, *args, **kwargs):
        # If password looks like raw (not hashed), hash it before save.
        if self.password and not self.password.startswith("pbkdf2_"):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.user


class AuthLogin(models.Model):
    """
    Demo auth table — avoid using in real projects. Use Django's User model instead.
    """
    username = models.CharField(max_length=200, unique=True)
    name = models.CharField(max_length=200)
    password = models.CharField(max_length=128)
    userid = models.AutoField(primary_key=True)

    def set_password(self, raw_password: str):
        self.password = make_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password(raw_password, self.password)

    def save(self, *args, **kwargs):
        if self.password and not self.password.startswith("pbkdf2_"):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username


class CFUser(models.Model):
    """
    CF_user: challenge user — keep for lab purposes but hash stored password.
    """
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=200)
    # store hashed password
    password = models.CharField(max_length=128)
    # password2 can be used to store e.g. HMAC or truncated hash in challenges,
    # but never store raw password twice in production.
    password2 = models.CharField(max_length=128, blank=True)

    def set_password(self, raw_password: str):
        self.password = make_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password(raw_password, self.password)

    def save(self, *args, **kwargs):
        if self.password and not self.password.startswith("pbkdf2_"):
            self.password = make_password(self.password)
        if self.password2 and not self.password2.startswith("pbkdf2_"):
            # preserve previous semantics but hash it
            self.password2 = make_password(self.password2)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username


# ------------------------
# OTP model (fixed)
# ------------------------
otp_regex = RegexValidator(
    regex=r"^\d{6}$", message="OTP must be a 6 digit string."
)


class OTP(models.Model):
    id = models.AutoField(primary_key=True)
    email = models.EmailField(max_length=254)
    otp = models.CharField(max_length=6, validators=[otp_regex])
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self, ttl_seconds: int = 300) -> bool:
        """Return True if OTP older than ttl_seconds."""
        cutoff = timezone.now() - timezone.timedelta(seconds=ttl_seconds)
        return self.created_at < cutoff

    def __str__(self):
        return f"{self.email} - {self.otp}"


# ------------------------
# Tickets model using AUTH_USER_MODEL
# ------------------------
class Tickits(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    tickit = models.CharField(max_length=40, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        try:
            return f"{self.tickit} {self.user.username}"
        except Exception:
            return self.tickit


# ------------------------
# SQL lab table (demo) — do not store plaintext passwords
# ------------------------
class SQLLabTable(models.Model):
    id = models.CharField(primary_key=True, max_length=200)
    # store hashed or intentionally vulnerable token (labelled)
    password = models.CharField(max_length=128)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password) -> bool:
        return check_password(raw_password, self.password)

    def save(self, *args, **kwargs):
        # If the stored password isn't already a pbkdf2 hash, hash it
        if self.password and not self.password.startswith("pbkdf2_"):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.id


# ------------------------
# Blogs model
# ------------------------
class Blogs(models.Model):
    id = models.AutoField(primary_key=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    blog_id = models.CharField(max_length=15, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.blog_id


# ------------------------
# Admin/session models (demo)
# ------------------------
class AFAdmin(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=200, unique=True)
    password = models.CharField(max_length=128)
    session_id = models.CharField(max_length=200, blank=True, null=True)
    last_login = models.DateTimeField(blank=True, null=True)
    logged_in = models.BooleanField(default=False)
    is_locked = models.BooleanField(default=False)
    failattempt = models.IntegerField(default=0)
    lockout_cooldown = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def set_password(self, raw_password: str):
        self.password = make_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password(raw_password, self.password)

    def save(self, *args, **kwargs):
        if self.password and not self.password.startswith("pbkdf2_"):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username


class AFSessionID(models.Model):
    id = models.AutoField(primary_key=True)
    session_id = models.CharField(max_length=200)
    user = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user


# ------------------------
# CSRF lab user table (simulated)
# ------------------------
class CSRFUserTbl(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=200, unique=True)
    password = models.CharField(max_length=128)
    balance = models.IntegerField(default=0)
    is_loggedin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def set_password(self, raw_password: str):
        self.password = make_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password(raw_password, self.password)

    def save(self, *args, **kwargs):
        if self.password and not self.password.startswith("pbkdf2_"):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username
