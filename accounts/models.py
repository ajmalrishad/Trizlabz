from django.contrib.auth.models import AbstractUser
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken

from .managers import CustomUserManager


# Create your models here.
class Customer(models.Model):
    customer_name = models.CharField(max_length=100, unique=True)
    address_line1 = models.CharField(max_length=100)
    address_line2 = models.CharField(max_length=100)
    profile_image = models.URLField(blank=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    pin = models.CharField(max_length=50)
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
    class Meta:
        db_table = 'Customer'


class Role(models.Model):
    role_name = models.CharField(max_length=100, unique=True)
    trizlabz_role = models.BooleanField(default=False)
    role_status = models.BooleanField(default=True)
    created_by = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.role_name
    class Meta:
        db_table = 'Role'


class Privilege(models.Model):
    role = models.ForeignKey(Role, related_name='privileges', on_delete=models.CASCADE)
    administration = models.BooleanField(default=False)
    customer_management = models.BooleanField(default=False)
    setup = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)
    def __str__(self):
        return self.role
    class Meta:
        db_table = 'Privilege'

# User Group Management
class UserGroup(models.Model):
    name = models.CharField(max_length=255, unique=True, blank=False)
    status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
    class Meta:
        db_table = 'UserGroup'



#User Management
class User(AbstractUser):
    first_name = None
    last_name = None
    username = models.CharField(max_length=200, null=False, unique=True)
    name = models.CharField(max_length=200, null=True)
    email = models.EmailField(max_length=255, unique=True)
    phone = models.CharField(max_length=20, unique=True)
    profile_image = models.URLField(max_length=500, null=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, null=True)
    trizlabz_user = models.BooleanField(default=False)
    tenet_id = models.CharField(max_length=200, null=True)
    cloud_username = models.CharField(max_length=200, null=True)
    cloud_password = models.CharField(max_length=200, null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    REQUIRED_FIELDS = ('email','phone')

    objects = CustomUserManager()

    def __str__(self):
        return self.email
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    class Meta:
        db_table = 'User'

class User_Groups_Assign(models.Model):
    group = models.ForeignKey(UserGroup, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        db_table = 'User_Groups_Assign'

class Customer_User(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.user.name

    class Meta:
        db_table = 'Customer_User'

# Variant_orAttachment Management
class Variant(models.Model):
    variant_id = models.AutoField(primary_key=True)
    variant_name = models.CharField(max_length=255, unique=True)
    variant_description = models.TextField()
    variant_status = models.BooleanField(default=True)
    created_by = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.variant_name
    class Meta:
        db_table = 'Variant'



class Attachment_or_Sensor_Master(models.Model):
    attachment_sensor_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    status = models.BooleanField(default=True)
    attachment_or_sensor = models.IntegerField(choices=((1, 'Attachment'), (2, 'Sensor')))
    created_by = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.name
    class Meta:
        db_table = 'Attachment_or_Sensor_Master'


class Variant_or_Attachment_or_Sensor(models.Model):
    variant = models.ForeignKey(Variant, on_delete=models.CASCADE, )
    attachment_or_sensor = models.ForeignKey(Attachment_or_Sensor_Master, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.variant
    class Meta:
        db_table = 'Variant_or_Attachment_or_Sensor'


# Map Management
class Map(models.Model):
    map_name = models.CharField(max_length=255, unique=True)
    map_description = models.CharField(max_length=255, null=True)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    map_layout = models.JSONField()
    path_layout = models.JSONField()
    map_status = models.BooleanField(default=True)
    created_by = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.map_name

    class Meta:
        db_table = 'Map'


# Deployment Management
class Deployment(models.Model):
    deployment_name = models.CharField(max_length=255, unique=True)
    deployment_status = models.BooleanField(default=True)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    created_by = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.deployment_name

    class Meta:
        db_table = 'Deployment'


class Deployment_Maps(models.Model):
    map = models.ForeignKey(Map, on_delete=models.CASCADE)
    deployment = models.ForeignKey(Deployment, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.deployment
    class Meta:
        db_table = 'Deployment_Maps'

#Vehicle Management
class Vehicle(models.Model):
    vehicle_label = models.CharField(max_length=100, unique=True)
    endpoint_id = models.CharField(max_length=100)
    application_id = models.CharField(max_length=100)
    vehicle_variant = models.CharField(max_length=100)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, null=True)
    vehicle_status = models.BooleanField(default=True)
    created_by = models.IntegerField(null=True)
    updated_by = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.vehicle_label
    class Meta:
        db_table ='Vehicle'


class Vehicle_Attachments(models.Model):
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE)
    attachment_option = models.ForeignKey(Attachment_or_Sensor_Master, on_delete=models.CASCADE)

    def __str__(self):
        return self.vehicle

    class Meta:
        db_table ='Vehicle_Attachments'


# Fleet Management
class Fleet(models.Model):
    name = models.CharField(max_length=255, unique=True, blank=False)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, null=True)
    status = models.BooleanField(default=True)
    created_by = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'Fleet'


class Fleet_Vehicle_Deployment(models.Model):
    fleet = models.ForeignKey(Fleet, on_delete=models.CASCADE)
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE)
    deployment = models.ForeignKey(Deployment, on_delete=models.CASCADE)

    def __str__(self):
        return self.fleet.name
    class Meta:
        db_table = 'Fleet_Vehicle_Deployment'

class Group_Deployment_Vehicle_Fleet_Customer(models.Model):
    group = models.ForeignKey(UserGroup, on_delete=models.CASCADE)
    deployment = models.ForeignKey(Deployment, on_delete=models.CASCADE)
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE)
    fleet = models.ForeignKey(Fleet, on_delete=models.CASCADE)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)

    def __str__(self):
        return self.group.name
    class Meta:
        db_table = 'Group_Deployment_Vehicle_Fleet_Customer'


# Action Management
class Action(models.Model):
    name = models.CharField(max_length=255, blank=False, unique=True)
    action_unit = models.TextField()
    status = models.BooleanField(default=True)
    created_by = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
    class Meta:
        db_table = 'Action'


# Mission Management
class Mission(models.Model):
    name = models.CharField(max_length=255, blank=False, unique=True)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    mission_details = models.JSONField()
    status = models.BooleanField(default=True)
    created_by = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
    class Meta:
        db_table = 'Mission'


class Mission_Fleet_Map_Deployment_Action(models.Model):
    mission = models.ForeignKey(Mission, on_delete=models.CASCADE)
    fleet = models.ForeignKey(Fleet, on_delete=models.CASCADE)
    map = models.ForeignKey(Map, on_delete=models.CASCADE)
    deployment = models.ForeignKey(Deployment, on_delete=models.CASCADE)
    action = models.ForeignKey(Action, on_delete=models.CASCADE)

    def __str__(self):
        return self.mission.name

    class Meta:
        db_table = 'Mission_Fleet_Map_Deployment_Action'

