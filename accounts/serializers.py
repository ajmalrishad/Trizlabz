from django.contrib import auth
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .models import User, Role, Customer, Privilege, Variant, Attachment_or_Sensor_Master, \
    Variant_or_Attachment_or_Sensor, Map, Deployment, Vehicle_Attachments, Vehicle, Fleet, UserGroup, Action


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    cloud_password = serializers.CharField(max_length=100, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = '__all__'

    def validate(self, attrs):
        username = attrs.get('username', '')
        if not username.isalnum():
            raise serializers.ValidationError(
                self.default_error_messages)
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=255, min_length=3)
    role = serializers.CharField(source='get_role', read_only=True)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = User.objects.get(username=obj['username'])

        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }

    def get_role(self, obj):
        return obj.role

    class Meta:
        model = User
        fields = ['username', 'password', 'role', 'tokens']

    def validate(self, attrs):
        username = attrs.get('username', '')
        password = attrs.get('password', '')
        role = attrs.get('role', '')
        user = auth.authenticate(username=username, password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        return {
            'username': username,
            'role': role,
        }


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': ('Token is invalid or expired')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')


class GetUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'user_id', 'name', 'username', 'email', 'phone', 'profile_image', 'role', 'trizlabz_user',
                  'cloud_username']
        password = serializers.CharField(max_length=68, min_length=6, write_only=True)
        cloud_password = serializers.CharField(max_length=100, min_length=6, write_only=True)


class DeleteUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'user_id', 'email']


class PrivilegeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Privilege
        fields = ('administration', 'customer_management', 'setup')


class RoleSerializer(serializers.ModelSerializer):
    privileges = PrivilegeSerializer(many=True)

    class Meta:
        model = Role
        fields = ('role_name', 'trizlabz_role', 'privileges')

    def create(self, validated_data):
        privileges_data = validated_data.pop('privileges')
        role = Role.objects.create(**validated_data)

        for privilege_data in privileges_data:
            Privilege.objects.create(role=role, **privilege_data)

        return role


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = '__all__'


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
    class Meta:
        model = Map
        fields = '__all__'


class DeploymentSerializer(serializers.ModelSerializer):
    list_of_maps_attached = MapSerializer(many=True, read_only=True)

    class Meta:
        model = Deployment
        fields = '__all__'


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

    class Meta:
        model = Vehicle
        fields = '__all__'


class FleetSerializer(serializers.ModelSerializer):
    vehicles = VehicleSerializer(many=True, read_only=True)
    deployment = DeploymentSerializer(many=True, read_only=True)

    class Meta:
        model = Fleet
        fields = '__all__'


# class CustomerCustomSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Customer
#         fields = ['customer_name']
#
#
# class CustomDeploymentSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Deployment
#         fields = ['deployment_name']


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
