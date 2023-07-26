from django.contrib.auth.models import AbstractUser
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


# Create your models here.
class Customer(models.Model):
    id = models.AutoField(primary_key=True)
    customer_name = models.CharField(max_length=100, unique=True)
    address_line1 = models.CharField(max_length=100)
    address_line2 = models.CharField(max_length=100)
    profile_image = models.URLField(blank=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    phone = models.CharField(max_length=20)
    mobile = models.CharField(max_length=20)
    spoc = models.CharField(max_length=100)
    email = models.EmailField()
    gst = models.CharField(max_length=20)
    tenetid = models.CharField(max_length=20)
    cloud_userName = models.CharField(max_length=100)
    cloud_password = models.CharField(max_length=100)
    customer_status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.customer_name


class User(AbstractUser):
    class Role(models.TextChoices):
        OPERATOR = "Operator"
        ADMINISTRATOR = "Administrator"
        SUPERVISOR = "Supervisor"
        SUPERADMIN = "Superadmin"

    # base_role = Role.OPERATOR
    username = models.CharField(max_length=200, null=False, unique=True)
    name = models.CharField(max_length=200, null=True)
    email = models.EmailField(max_length=255, unique=True)
    phone = models.CharField(max_length=20, unique=True)
    profile_image = models.URLField(max_length=500, null=True)
    role = models.CharField(max_length=50, choices=Role.choices)
    trizlabz_user = models.BooleanField(default=True)
    tenet_id = models.CharField(max_length=200, null=True)
    cloud_username = models.CharField(max_length=200, null=True)
    cloud_password = models.CharField(max_length=200, null=True)
    customer_id = models.OneToOneField(Customer, on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }


class Role(models.Model):
    role_name = models.CharField(max_length=100, unique=True)
    trizlabz_role = models.BooleanField(default=False)
    role_status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)


class Privilege(models.Model):
    role = models.ForeignKey(Role, related_name='privileges', on_delete=models.CASCADE)
    administration = models.BooleanField(default=False)
    customer_management = models.BooleanField(default=False)
    setup = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)


class Variant(models.Model):
    variant_id = models.AutoField(primary_key=True)
    variant_name = models.CharField(max_length=255, unique=True)
    variant_description = models.TextField()
    variant_status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.variant_name


class Attachment_or_Sensor_Master(models.Model):
    attachment_sensor_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    status = models.BooleanField(default=True)
    attachment_or_sensor = models.IntegerField(choices=((1, 'Attachment'), (2, 'Sensor')))
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.name


class Variant_or_Attachment_or_Sensor(models.Model):
    variant = models.ForeignKey(Variant, on_delete=models.CASCADE, )
    attachment_or_sensor = models.ForeignKey(Attachment_or_Sensor_Master, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.variant


# Map Management
class Map(models.Model):
    map_name = models.CharField(max_length=255, unique=True)
    map_description = models.CharField(max_length=255, null=True)
    customer_id = models.CharField(max_length=255)
    map_layout = models.URLField()
    path_layout = models.JSONField()
    map_status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.map_name


# Deployment Management
class Deployment(models.Model):
    deployment_name = models.CharField(max_length=255, unique=True)
    deployment_status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.deployment_name


class Deployment_Maps(models.Model):
    map = models.ForeignKey(Map, on_delete=models.CASCADE)
    deployment = models.ForeignKey(Deployment, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.deployment


class Vehicle(models.Model):
    vehicle_label = models.CharField(max_length=100, unique=True)
    endpoint_id = models.CharField(max_length=100)
    application_id = models.CharField(max_length=100)
    vehicle_variant = models.CharField(max_length=100)
    customer_id = models.CharField(max_length=100)
    vehicle_status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.vehicle_label


class Vehicle_Attachments(models.Model):
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE)
    attachment_option = models.ForeignKey(Attachment_or_Sensor_Master, on_delete=models.CASCADE)

    def __str__(self):
        return self.vehicle


# Fleet Management
class Fleet(models.Model):
    name = models.CharField(max_length=255, unique=True, blank=False)
    status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Fleet_Vehicle_Deployment(models.Model):
    fleet = models.ForeignKey(Fleet, on_delete=models.CASCADE)
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE)
    deployment = models.ForeignKey(Deployment, on_delete=models.CASCADE)

    def __str__(self):
        return self.fleet.name


# User Group Management
class UserGroup(models.Model):
    name = models.CharField(max_length=255, unique=True, blank=False)
    status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Group_Deployment_Vehicle_Fleet_Customer(models.Model):
    group = models.ForeignKey(UserGroup, on_delete=models.CASCADE)
    deployment = models.ForeignKey(Deployment, on_delete=models.CASCADE)
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE)
    fleet = models.ForeignKey(Fleet, on_delete=models.CASCADE)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)

    def __str__(self):
        return self.group.name


# Mission Management
class Action(models.Model):
    name = models.CharField(max_length=255, blank=False, unique=True)
    status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

