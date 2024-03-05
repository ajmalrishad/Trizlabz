from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .models import User, Role, Customer, Privilege, Variant, Attachment_or_Sensor_Master, \
    Variant_or_Attachment_or_Sensor, Map, Deployment, Vehicle_Attachments, Vehicle, Fleet, UserGroup, Action, Mission, \
    Customer_User,User_Groups_Assign


class FleetSerializer:
    pass
class VehicleSerializer:
    pass
class DeploymentSerializer:
    pass


class CustomerSerializer(serializers.ModelSerializer):
    fleets = FleetSerializer()
    vehicles = VehicleSerializer()
    deployments = DeploymentSerializer()

    class Meta:
        model = Customer
        fields = '__all__'


class PrivilegeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Privilege
        fields = ('administration', 'customer_management', 'setup')


class RoleSerializer(serializers.ModelSerializer):
    privileges = PrivilegeSerializer(many=True)

    class Meta:
        model = Role
        fields = ('id', 'role_name', 'trizlabz_role', 'privileges')

    def create(self, validated_data):
        privileges_data = validated_data.pop('privileges')
        role = Role.objects.create(**validated_data)

        for privilege_data in privileges_data:
            Privilege.objects.create(role=role, **privilege_data)

        return role

    def update(self, instance, validated_data):
        privileges_data = validated_data.pop('privileges', [])
        instance = super().update(instance, validated_data)

        if privileges_data:
            instance.privileges.all().delete()
            for privilege_data in privileges_data:
                Privilege.objects.create(role=instance, **privilege_data)

        return instance


class RegisterSerializer(serializers.ModelSerializer):
    role_id = serializers.IntegerField(required=False)
    customer_id = serializers.ListField(child=serializers.CharField(), write_only=True, required=False)
    user_group_ids = serializers.ListField(child=serializers.IntegerField(), write_only=True,
                                           required=False)  # Change this to match your field name
    password = serializers.CharField(write_only=True)
    trizlabz_user = serializers.BooleanField(write_only=True, required=False, default=False)

    class Meta:
        model = User
        exclude = ('last_login', 'is_superuser', 'is_staff', 'is_active', 'date_joined', 'groups', 'user_permissions')

    def create(self, validated_data):
        password = validated_data.pop('password')
        customer_ids = validated_data.pop('customer_id', [])
        user_group_ids = validated_data.pop('user_group_ids', [])  # Remove user_group_ids from validated_data

        # Hash the password
        hashed_password = make_password(password)

        user = User.objects.create(password=hashed_password, **validated_data)

        if validated_data.get('trizlabz_user'):
            for customer_id in customer_ids:
                try:
                    customer = Customer.objects.get(id=customer_id, customer_status=1)
                    Customer_User.objects.create(user=user, customer=customer)
                except Customer.DoesNotExist:
                    pass
        else:
            if customer_ids:
                try:
                    customer = Customer.objects.get(id=customer_ids[0], customer_status=1)
                    Customer_User.objects.create(user=user, customer=customer)
                except Customer.DoesNotExist:
                    pass

        return user


class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=255, min_length=3)
    role = serializers.CharField(read_only=True)
    tokens = serializers.SerializerMethodField()
    customer_id = serializers.ListField(write_only=True, required=False)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        user = authenticate(username=username, password=password)

        if user:
            if not user.is_active:
                raise AuthenticationFailed('Account disabled, contact admin')

            attrs['user'] = user
            return attrs
        else:
            raise AuthenticationFailed('Invalid credentials, try again')

    def get_role(self, obj):
        return obj.role
        # return user.obj.role

    class Meta:
        model = User
        fields = ['username', 'password', 'role', 'tokens','customer_id']


class GetUserSerializer(serializers.ModelSerializer):
    customer_id = serializers.ListField(write_only=True, required=False)
    class Meta:
        model = User
        exclude = ['password', 'last_login', 'is_staff', 'is_superuser', 'is_active', 'date_joined', 'created_at',
                   'updated_at', 'groups', 'user_permissions']


class UpdateUserSerializer(serializers.ModelSerializer):
    customer_id = serializers.ListField(write_only=True, required=False)
    # password = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = '__all__'
        extra_kwargs = {
            'password': {'write_only': True},
            'last_login': {'write_only': True},
            'is_superuser': {'write_only': True},
            'is_staff': {'write_only': True},
            'is_active': {'write_only': True},
            'date_joined': {'write_only': True},
            'groups': {'write_only': True},
            'user_permissions': {'write_only': True},
            'username': {'required': False},  # Remove username requirement
            'email': {'required': False},  # Remove email requirement
            'phone': {'required': False},  # Remove phone requirement
        }

    def update(self, instance, validated_data):
        customer_ids = validated_data.pop('customer_id', [])

        customers = Customer.objects.filter(id__in=customer_ids, customer_status=1)
        if len(customers) != len(customer_ids):
            raise serializers.ValidationError("One or more customers do not exist or have invalid status")

        for customer in customers:
            Customer_User.objects.update_or_create(user=instance, customer=customer)

        return super().update(instance, validated_data)


class DeleteUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'user_id', 'email']


class Attachment_SensorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment_or_Sensor_Master
        fields = '__all__'


class Variant_or_Attachment_or_Sensor_Serializer(serializers.ModelSerializer):
    class Meta:
        model = Variant_or_Attachment_or_Sensor
        fields = '__all__'


class VariantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Variant
        fields = '__all__'


class GetVariantSerializer(serializers.ModelSerializer):
    variant = Variant_or_Attachment_or_Sensor_Serializer(many=True, read_only=True)
    attachment_or_sensor = Variant_or_Attachment_or_Sensor_Serializer(many=True, read_only=True)

    class Meta:
        model = Variant
        fields = ['variant_id', 'variant_name', 'variant_description', 'variant_status', 'variant',
                  'attachment_or_sensor']


class GetSensor_AttachmentSerializer(serializers.ModelSerializer):
    variant = Variant_or_Attachment_or_Sensor_Serializer(many=True, read_only=True)
    attachment_or_sensor = Variant_or_Attachment_or_Sensor_Serializer(many=True, read_only=True)

    class Meta:
        model = Variant_or_Attachment_or_Sensor
        fields = '__all__'


# Map Management
class MapSerializer(serializers.ModelSerializer):
    customer_id = serializers.CharField(required=False)  # Optional field for customer ID

    class Meta:
        model = Map
        fields = ['id', 'map_name', 'map_description', 'customer_id', 'map_layout', 'path_layout']


class DeploymentSerializer(serializers.ModelSerializer):
    map_id = MapSerializer(many=True, read_only=True)
    customer_id = serializers.PrimaryKeyRelatedField(source='customer', read_only=True)
    user_id = serializers.SerializerMethodField()

    class Meta:
        model = Deployment
        fields = ['id', 'deployment_name', 'deployment_status', 'customer_id', 'map_id', 'user_id']

    def get_user_id(self, obj):
        try:
            return Customer_User.objects.get(customer_id=obj.customer_id).user_id
        except Customer_User.DoesNotExist:
            return None


class AttachmentOptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment_or_Sensor_Master
        fields = ['attachment_sensor_id', 'name']


class VehicleAttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vehicle_Attachments
        fields = '__all__'


class VehicleSerializer(serializers.ModelSerializer):
    attachment_option = Attachment_SensorSerializer(many=True, read_only=True)
    customer = CustomerSerializer() 


    class Meta:
        model = Vehicle
        fields = '__all__'


class FleetSerializer(serializers.ModelSerializer):
    vehicles = VehicleSerializer(many=True, read_only=True)
    deployment = DeploymentSerializer(many=True, read_only=True)
    customer = CustomerSerializer(many=True, read_only=True)

    class Meta:
        model = Fleet
        fields = '__all__'


class GroupSerializer(serializers.ModelSerializer):
    vehicle = VehicleSerializer(many=True, read_only=True)
    deployment = DeploymentSerializer(many=True, read_only=True)
    customer = CustomerSerializer(many=True, read_only=True)
    fleet = FleetSerializer(many=True, read_only=True)

    class Meta:
        model = UserGroup
        fields = '__all__'


class ActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Action
        fields = '__all__'


class MissionSerializer(serializers.ModelSerializer):
    customer = CustomerSerializer(read_only=True)
    deployment = DeploymentSerializer(many=True, read_only=True)
    map = MapSerializer(many=True, read_only=True)
    fleet = FleetSerializer(many=True, read_only=True)
    action = ActionSerializer(many=True, read_only=True)

    class Meta:
        model = Mission
        fields = '__all__'

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField(write_only=True)