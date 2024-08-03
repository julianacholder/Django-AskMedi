from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import uuid


class UserSummary(models.Model):
    user_id = models.CharField(max_length=255)  
    summary_content = models.TextField()
    diagnosis_content = models.TextField()  
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Summary for User {self.user_id} at {self.timestamp}"


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    fullname = models.CharField(max_length=255)
    gender = models.CharField(max_length=10, choices=[('male', 'Male'), ('female', 'Female')])
    age = models.IntegerField()
    is_verified = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)

    def set_otp(self):
        import random
        self.otp = str(random.randint(100000, 999999))
        self.otp_created_at = timezone.now()
        self.save()

    def is_otp_valid(self):
        if not self.otp_created_at:
            return False
        return (timezone.now() - self.otp_created_at).total_seconds() < 300

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'fullname', 'gender', 'age']

    def __str__(self):
        return self.email

class VerificationToken(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
