import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


# Create your models here.
class User(AbstractUser):
    class Role(models.TextChoices):
        OPERATOR = "Operator"
        ADMINISTRATOR = "Administrator"
        SUPERVISOR = "Supervisor"
        SUPERADMIN = "Superadmin"

    # base_role = Role.OPERATOR
    username = models.CharField(max_length=200, null=False,unique=True)
    name = models.CharField(max_length=200, null=True)
    user_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    email = models.EmailField(max_length=255, unique=True)
    phone = models.CharField(max_length=20, unique=True)
    profile_image = models.URLField(max_length=500, null=True)
    role = models.CharField(max_length=50, choices=Role.choices)
    trizlabz_user = models.BooleanField(default=True)
    cloud_username = models.CharField(max_length=200, null=True)
    cloud_password = models.CharField(max_length=200, null=True)


    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
