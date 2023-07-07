from django.contrib import auth
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .models import User, Role, Customer, Privilege, Variant, Attachment, Sensor


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


class AttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment
        fields = '__all__'


class SensorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sensor
        fields = '__all__'


class VariantSerializer(serializers.ModelSerializer):
    attachment_option = AttachmentSerializer(many=True)
    sensor_option = SensorSerializer(many=True)

    class Meta:
        model = Variant
        fields = ['variant_id', 'variant_name', 'variant_description', 'attachment_option', 'sensor_option']

    def create(self, validated_data):
        attachment_data = validated_data.pop('attachment_option')
        sensor_data = validated_data.pop('sensor_option')

        variant = Variant.objects.create(**validated_data)

        for attachment in attachment_data:
            Attachment.objects.create(variant=variant, **attachment)

        for sensor in sensor_data:
            Sensor.objects.create(variant=variant, **sensor)

        return variant

    def update(self, instance, validated_data):
        attachment_data = validated_data.pop('attachment_option', [])
        sensor_data = validated_data.pop('sensor_option', [])

        instance.variant_name = validated_data.get('variant_name', instance.variant_name)
        instance.variant_description = validated_data.get('variant_description', instance.variant_description)
        instance.save()

        self._update_attachments(instance, attachment_data)
        self._update_sensors(instance, sensor_data)

        return instance

    def _update_attachments(self, instance, attachment_data):
        existing_attachments = instance.attachment_option.all()
        existing_attachments_ids = [item.id for item in existing_attachments]
        updated_attachments = []
        created_attachments = []

        for attachment in attachment_data:
            attachment_id = attachment.get('attachment_id', None)
            if attachment_id and attachment_id in existing_attachments_ids:
                updated_attachment = existing_attachments.get(id=attachment_id)
                updated_attachment.attachment_name = attachment.get('attachment_name',
                                                                    updated_attachment.attachment_name)
                updated_attachment.save()
                updated_attachments.append(updated_attachment)
            else:
                created_attachments.append(Attachment(variant=instance, **attachment))

        Attachment.objects.bulk_create(created_attachments)

        for attachment in existing_attachments:
            if attachment not in updated_attachments:
                attachment.delete()

    def _update_sensors(self, instance, sensor_data):
        existing_sensors = instance.sensor_option.all()
        existing_sensors_ids = [item.id for item in existing_sensors]
        updated_sensors = []
        created_sensors = []

        for sensor in sensor_data:
            sensor_id = sensor.get('sensor_id', None)
            if sensor_id and sensor_id in existing_sensors_ids:
                updated_sensor = existing_sensors.get(id=sensor_id)
                updated_sensor.sensor_name = sensor.get('sensor_name', updated_sensor.sensor_name)
                updated_sensor.save()
                updated_sensors.append(updated_sensor)
            else:
                created_sensors.append(Sensor(variant=instance, **sensor))

        Sensor.objects.bulk_create(created_sensors)

        for sensor in existing_sensors:
            if sensor not in updated_sensors:
                sensor.delete()
