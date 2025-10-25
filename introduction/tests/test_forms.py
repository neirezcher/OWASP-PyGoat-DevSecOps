from django.test import TestCase
from django.contrib.auth.models import User
from introduction.forms import NewUserForm


class NewUserFormTests(TestCase):
    def test_form_valid_data_creates_user(self):
        form = NewUserForm(data={
            'username': 'newuser',
            'email': 'test@example.com',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        })
        self.assertTrue(form.is_valid())
        user = form.save()
        self.assertIsInstance(user, User)
        self.assertEqual(user.email, 'test@example.com')
        self.assertTrue(user.check_password('StrongPass123!'))

    def test_form_rejects_mismatched_passwords(self):
        form = NewUserForm(data={
            'username': 'baduser',
            'email': 'bad@example.com',
            'password1': 'Password123!',
            'password2': 'Password321!',
        })
        self.assertFalse(form.is_valid())
        self.assertIn('password2', form.errors)

    def test_form_requires_email(self):
        form = NewUserForm(data={
            'username': 'noemail',
            'password1': 'Password123!',
            'password2': 'Password123!',
        })
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)

    def test_form_rejects_duplicate_email(self):
        """If you implemented the clean_email method"""
        User.objects.create_user(username='existing', email='dup@example.com', password='Password123!')
        form = NewUserForm(data={
            'username': 'newone',
            'email': 'dup@example.com',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        })
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)
