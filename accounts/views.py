from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User, Role, Customer, Variant, Attachment_or_Sensor_Master, Variant_or_Attachment_or_Sensor, Map, \
    Deployment, Deployment_Maps, Vehicle, Vehicle_Attachments, Fleet, Fleet_Vehicle_Deployment, UserGroup, \
    Group_Deployment_Vehicle_Fleet_Customer, Action, Mission, Mission_Fleet_Map_Deployment_Action, Customer_User
from .serializers import RegisterSerializer, LoginSerializer, GetUserSerializer, UpdateUserSerializer, \
    DeleteUserSerializer, RoleSerializer, CustomerSerializer, VariantSerializer, Attachment_SensorSerializer, \
    MapSerializer, DeploymentSerializer, VehicleSerializer, FleetSerializer, GroupSerializer, ActionSerializer, \
    MissionSerializer


# User Management

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        customer_id = request.data.get('customer_id')
        role_id = request.data.get('role_id')
        group_id = request.data.get('user_group', None)

        try:
            customer = Customer.objects.get(id=customer_id, customer_status=1)
        except Customer.DoesNotExist:
            return Response({"error": "Customer does not exist or has an invalid status"},
                            status=status.HTTP_400_BAD_REQUEST)

        role = None
        if role_id:
            try:
                role = Role.objects.get(id=role_id)
            except Role.DoesNotExist:
                return Response({"error": "Role does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check if group name exists in request data, otherwise set it to None
        if 'user_group' in request.data:
            group_id = request.data['user_group']
        else:
            group_id = None

        # Save the user after all validations
        user = serializer.save()

        Customer_User.objects.create(user=user, customer=customer)

        if role:
            user.role = role
            user.save()

        # Validate group name
        if group_id:
            try:
                user_group = UserGroup.objects.get(id=group_id)
            except UserGroup.DoesNotExist:
                return Response({"error": f"Invalid group name: {group_id}"}, status=status.HTTP_400_BAD_REQUEST)
            user.groups.set([user_group.id])  # Set the user's group

        response_data = serializer.data.copy()
        response_data['customer_id'] = customer.id
        response_data['user_group'] = {'id': group_id}

        response = {
            "message": "User added successfully",
            "status": "success",
            "data": response_data
        }

        return Response(response, status=status.HTTP_201_CREATED)



# login user
class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        message = "User logged in successfully"
        response_data = {
            'message': message,
            'data': {
                'username': user.username,
                # 'role': user.role,
                'role': user.role_id,
                'trizlabz_user': user.trizlabz_user,
                'cloud_username': user.cloud_username,
                'token': user.tokens(),
            }
        }

        return Response(response_data, status=status.HTTP_200_OK)


# logout user
class LogoutAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        refresh_token = self.request.data.get('refresh_token')

        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({"status": "User logged out successfully"})
            except TokenError as e:
                return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"detail": "No refresh token provided"}, status=status.HTTP_400_BAD_REQUEST)


# get all users
class GetUsersAPIView(generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = GetUserSerializer

    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        # Get query parameters
        user_id = self.request.query_params.get('user_id')
        customer_id = self.request.query_params.get('customer_id')
        username = self.request.query_params.get('username')
        user_status = self.request.query_params.get('user_status')

        if user_id:
            try:
                user = User.objects.get(id=user_id)
                serializer = self.get_serializer(user)
                response_data = {
                    'message': 'User retrieved successfully',
                    'status': 'success',
                    'data': serializer.data
                }
                return Response(response_data, status=200)
            except User.DoesNotExist:
                response_data = {
                    'message': 'User not found.',
                    'status': 'error'
                }
                return Response(response_data, status=404)

        users_data = self.get_queryset()
        # users_data=Customer_User.objects.all()

        if username:
            users_data = users_data.filter(username=username)
            # users_data = users_data.filter(customer=customer_id)


        if user_status:
            users_data = users_data.filter(is_active=user_status)

        if customer_id:
            # Filter users based on the provided customer_id
            users_data = users_data.filter(customer_user__customer_id=customer_id)

        serializer = self.get_serializer(users_data, many=True)
        response_data = {
            'message': 'User details listed successfully',
            'status': 'success',
            'data': serializer.data
        }
        return Response(response_data, status=200)


class UpdateUsersAPIView(generics.GenericAPIView):
    serializer_class = UpdateUserSerializer

    permission_classes = (IsAuthenticated,)

    def put(self, request, id):
        try:
            user = User.objects.get(id=id)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        update_user_data = request.data

        # Check if customer_ids and role_id are present in the update data
        customer_ids = update_user_data.get('customer_id', [])
        role_id = update_user_data.get('role_id', None)
        user_group = update_user_data.get('user_group', None)

        if role_id is not None:
            try:
                role = Role.objects.get(id=role_id)
                user.role = role
                user.save()
            except Role.DoesNotExist:
                return Response({'message': "No such role or invalid role_id"},
                                status=status.HTTP_404_NOT_FOUND)

        if user_group is not None:
            try:
                user_group = UserGroup.objects.get(name=user_group)
            except UserGroup.DoesNotExist:
                return Response({'message': "No such user group or invalid user_group_name"},
                                status=status.HTTP_404_NOT_FOUND)

        if customer_ids:
            customers = Customer.objects.filter(id__in=customer_ids, customer_status=1)
            if len(customers) != len(customer_ids):
                return Response({'message': "One or more customers do not exist or have invalid status"},
                                status=status.HTTP_404_NOT_FOUND)

            # Delete the old entries in the Customer_User table for this user
            Customer_User.objects.filter(user=user).delete()

            # Save the user instance
            for customer in customers:
                user.customer = customer
                user.save()

                # Create new entries in the Customer_User table for this Customer_User
                customer_user = Customer_User.objects.create(user=user, customer=customer, user_group=user_group)

        serializer = self.serializer_class(user, data=update_user_data, partial=True)
        if serializer.is_valid():
            serializer.save()  # Save the instance manually
            response = {
                "message": "User updated successfully",
                "data": serializer.data,
                "user_group": serializer.data.get("user_grop"),
                "user_type": serializer.data.get("user_type"),
            }
            return Response(response, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteUsersAPIView(generics.GenericAPIView):
    serializer_class = DeleteUserSerializer

    permission_classes = (IsAuthenticated,)

    def delete(self, request, id):
        try:
            user = User.objects.get(id=id)
            user.is_active = False
            user.save()
            return Response({'message': 'User deleted successfully'})
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=404)


# Role Management
class CreateRoleView(generics.GenericAPIView):
    serializer_class = RoleSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            role_name = serializer.validated_data['role_name']

            # Check if a role with the same role_name already exists
            if Role.objects.filter(role_name=role_name).exists():
                return Response({'message': 'Role with the same name already exists.'}, status=400)

            trizlabz_role = request.data.get('trizlabz_role', 'false')
            privileges_data = request.data.get('privileges',
                                               [])  # Get privileges data from the request, default to an empty list
            role = serializer.save()

            response_data = {
                'message': 'Role added successfully',
                'status': 'success',
                'data': {
                    'id': role.id,
                    'role_name': role.role_name,
                    'trizlabz_role': trizlabz_role,
                    'privileges': privileges_data,  # Include the privileges data from the request
                }
            }
            return Response(response_data, status=201)
        return Response(serializer.errors, status=400)


class RoleUpdateView(generics.UpdateAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    permission_classes = (IsAuthenticated,)

    def put(self, request, role_id):
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            return Response({'message': 'Role not found.'}, status=404)

        serializer = RoleSerializer(role, data=request.data, partial=True)  # Use partial=True to allow partial updates
        if serializer.is_valid():
            serializer.save()
            response = {
                "message": "User Updated Successfully",
                "status": "success",
                "data": serializer.data
            }
            return Response(response)
        return Response(serializer.errors, status=400)


class RoleDeleteView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request, role_id):
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            return Response({'message': 'Role not found.'}, status=404)

        role.role_status = False
        role.save()
        return Response({'message': 'Role deleted successfully.'}, status=200)


class GetRoleAPIView(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    def get(self, request, *args, **kwargs):
        # Get query parameters
        role_id = self.request.query_params.get('role_id')
        role_name = self.request.query_params.get('role_name')
        role_status = self.request.query_params.get('role_status')
        trizlabz_role = self.request.query_params.get('trizlabz_role')

        if role_id:
            try:
                roles = Role.objects.get(id=role_id)
                serializer = self.get_serializer(roles)
                response_data = {
                    'message': 'Role listed successfully',
                    'status': 'success',
                    'data': serializer.data
                }
                return Response(response_data, status=200)
            except Role.DoesNotExist:
                return Response({'message': 'Role not found.'}, status=404)

        if role_name and role_status and trizlabz_role:
            roles = self.queryset.filter(role_name=role_name, role_status=role_status, trizlabz_role=trizlabz_role)
        elif role_name:
            roles = self.queryset.filter(role_name=role_name)
        elif role_status:
            roles = self.queryset.filter(role_status=role_status)
        elif trizlabz_role:
            roles = self.queryset.filter(trizlabz_role=trizlabz_role)
        else:
            roles = self.get_queryset()

        serializer = self.get_serializer(roles, many=True)
        response_data = {
            'message': 'Role listed successfully',
            'status': 'success',
            'data': serializer.data
        }
        return Response(response_data, status=200)


# Customer Management
class CustomerCreateView(generics.CreateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = CustomerSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            customer_name = serializer.validated_data['customer_name']

            # Check if a customer with the same name already exists
            if Customer.objects.filter(customer_name=customer_name).exists():
                return Response({'message': 'Customer with the same name already exists.'}, status=400)

            customer = serializer.save()
            response = {
                "message": "Customer Added Successfully",
                "data": CustomerSerializer(customer).data

            }
            return Response(response, status=201)

        return Response(serializer.errors, status=400)


class GetCustomerAPIView(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer

    def get(self, request, *args, **kwargs):
        # Get query parameters
        customer_id = self.request.query_params.get('customer_id')
        customer_name = self.request.query_params.get('customer_name')
        customer_status = self.request.query_params.get('customer_status')

        if customer_id:
            try:
                customer = Customer.objects.get(id=customer_id)
                serializer = self.get_serializer(customer)
                response_data = {
                    'message': 'Customer retrieved successfully',
                    'status': 'success',
                    'data': serializer.data
                }
                return Response(response_data, status=status.HTTP_200_OK)
            except Customer.DoesNotExist:
                return Response({'message': 'Customer not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Filter customers based on query parameters
        if customer_name and customer_status:
            customers = self.queryset.filter(customer_name=customer_name, status=customer_status)
        elif customer_name:
            customers = self.queryset.filter(customer_name=customer_name)
        elif customer_status:
            customers = self.queryset.filter(customer_status=customer_status)
        else:
            customers = self.get_queryset()

        serializer = self.get_serializer(customers, many=True)
        response_data = {
            'message': 'Customer listing successfully',
            'status': 'success',
            'data': serializer.data
        }

        # Include related data for each customer
        for customer_data in response_data['data']:
            customer_id = customer_data['id']
            customer = Customer.objects.get(id=customer_id)

            # Include related fleets
            customer_data['fleets'] = FleetSerializer(customer.fleet_set.all(), many=True).data

            # Include related vehicles
            customer_data['vehicles'] = VehicleSerializer(customer.vehicle_set.all(), many=True).data

            # Include related deployments
            customer_data['deployments'] = DeploymentSerializer(customer.deployment_set.all(), many=True).data

        return Response(response_data, status=status.HTTP_200_OK)


class UpdateCustomerAPIView(generics.UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    lookup_field = 'id'

    def put(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)


class DeleteCustomerAPIView(generics.DestroyAPIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request, id):
        try:
            customer = Customer.objects.get(id=id)
        except Customer.DoesNotExist:
            return Response({'message': 'customer not found.'}, status=404)

        customer.customer_status = False
        customer.save()
        response = {
            'message': 'customer deleted successfully',
            'status': 'success',
            'data': {
                'customer_id': customer.id,
                'customer_name': customer.customer_name,
                'customer_status': customer.customer_status,
            }
        }
        return Response(response, status=200)


# Attachment or Sensor
class Attachment_Sensor(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        attachment_or_sensor = self.request.data.get('attachment_or_sensor')
        name = self.request.data.get('name')

        if attachment_or_sensor == "1":
            # Handling attachments
            if Attachment_or_Sensor_Master.objects.filter(name=name,
                                                          attachment_or_sensor=attachment_or_sensor).exists():
                return Response({"message": "An attachment with the same name already exists."},
                                status=status.HTTP_400_BAD_REQUEST)

            attachment_data = {
                # Extract the attachment data from the request data
                'name': name,
                'description': self.request.data.get('description'),
                'attachment_or_sensor': self.request.data.get('attachment_or_sensor')
                # Add any additional fields specific to attachments
            }
            attachment_serializer = Attachment_SensorSerializer(
                data=attachment_data)  # Replace 'AttachmentSerializer' with your actual attachment serializer

            if attachment_serializer.is_valid():
                attachment_serializer.save()
                response_data = {
                    'message': 'Attachment added successfully',
                    'status': 'success',
                    'data': attachment_serializer.data
                }
                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(attachment_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        elif attachment_or_sensor == "2":
            # Handling sensors
            if Attachment_or_Sensor_Master.objects.filter(name=name,
                                                          attachment_or_sensor=attachment_or_sensor).exists():
                return Response({"message": "A sensor with the same name already exists."},
                                status=status.HTTP_400_BAD_REQUEST)

            sensor_data = {
                # Extract the sensor data from the request data
                'name': name,
                'description': self.request.data.get('description'),
                'attachment_or_sensor': self.request.data.get('attachment_or_sensor')
                # Add any additional fields specific to sensors
            }
            sensor_serializer = Attachment_SensorSerializer(
                data=sensor_data)  # Replace 'SensorSerializer' with your actual sensor serializer

            if sensor_serializer.is_valid():
                sensor_serializer.save()
                response_data = {
                    'message': 'Sensor added successfully',
                    'status': 'success',
                    'data': sensor_serializer.data
                }
                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(sensor_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': 'Invalid attachment_or_sensor value.'}, status=status.HTTP_400_BAD_REQUEST)


class GetAttachment_SensorAPIView(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        # Get query parameters
        attachment_sensor_id = self.request.query_params.get('attachment_sensor_id')
        name = self.request.query_params.get('name')
        attachment_or_sensor = self.request.query_params.get('attachment_or_sensor')
        status = self.request.query_params.get('status')

        if attachment_sensor_id:
            try:
                attachment_sensor = Attachment_or_Sensor_Master.objects.get(attachment_sensor_id=attachment_sensor_id)
                serializer = Attachment_SensorSerializer(attachment_sensor)
                response_data = {
                    'message': 'Attachment or Sensor retrieved successfully',
                    'status': 'success',
                    'data': serializer.data
                }
                return Response(response_data, status=200)
            except Attachment_or_Sensor_Master.DoesNotExist:
                return Response({'message': 'Attachment or Sensor not found.'}, status=404)

        if attachment_or_sensor == "1":
            try:
                attachments = Attachment_or_Sensor_Master.objects.filter(attachment_or_sensor=attachment_or_sensor)
                serializer = Attachment_SensorSerializer(attachments, many=True)
                response_data = {
                    'message': 'Attachments listed successfully',
                    'status': 'success',
                    'data': serializer.data
                }
                return Response(response_data, status=200)
            except Attachment_or_Sensor_Master.DoesNotExist:
                return Response({'message': 'Attachment not found.'}, status=404)

        elif attachment_or_sensor == "2":
            try:
                sensors = Attachment_or_Sensor_Master.objects.filter(attachment_or_sensor=attachment_or_sensor)
                serializer = Attachment_SensorSerializer(sensors, many=True)
                response_data = {
                    'message': 'Sensors listed successfully',
                    'status': 'success',
                    'data': serializer.data
                }
                return Response(response_data, status=200)
            except Attachment_or_Sensor_Master.DoesNotExist:
                return Response({'message': 'Sensor not found.'}, status=404)

        if name:
            try:
                attachments = Attachment_or_Sensor_Master.objects.filter(name=name)
                serializer = Attachment_SensorSerializer(attachments,
                                                         many=True)
                response_data = {
                    'message': 'Attachment or Sensor listing successfully',
                    'status': 'success',
                    'data': serializer.data
                }
                return Response(response_data, status=200)
            except Attachment_or_Sensor_Master.DoesNotExist:
                return Response({'message': 'Attachment or Sensor not found.'}, status=404)

        if status:
            try:
                attachments = Attachment_or_Sensor_Master.objects.filter(status=status)
                serializer = Attachment_SensorSerializer(attachments,
                                                         many=True)
                response_data = {
                    'message': 'Attachment or Sensor listing successfully',
                    'status': 'success',
                    'data': serializer.data
                }
                return Response(response_data, status=200)
            except Attachment_or_Sensor_Master.DoesNotExist:
                return Response({'message': 'Attachment or Sensor not found.'}, status=404)

        else:
            return Response({'message': 'Invalid parameters.'}, status=400)


class UpdateAttachmentAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def put(self, request, id):
        try:
            attachment_or_sensor = Attachment_or_Sensor_Master.objects.get(attachment_sensor_id=id)
        except Attachment_or_Sensor_Master.DoesNotExist:
            return Response({'message': 'Attachment or sensor does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = Attachment_SensorSerializer(attachment_or_sensor, data=request.data)
        if serializer.is_valid():
            serializer.save()
            response = {
                'message': "Attachment or sensor Updated Successfully",
                "status": "success",
                "data": serializer.data
            }
            return Response(response, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteAttachment_SensorAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request):
        attachment_sensor_id = self.request.query_params.get('id')

        try:
            attachment_or_sensor = Attachment_or_Sensor_Master.objects.get(attachment_sensor_id=attachment_sensor_id)
        except Attachment_or_Sensor_Master.DoesNotExist:
            return Response({'message': 'Attachment or sensor does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        attachment_or_sensor.status = False
        attachment_or_sensor.save()
        response = {
            message: 'Attachment or sensor deleted successfully',
            'data': {
                'message': message,
                'status': 'success',
            }

        }
        return Response(response, status=status.HTTP_204_NO_CONTENT)


# Variant Management Apis
class AddVariantCreateView(generics.CreateAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Variant.objects.all()
    serializer_class = VariantSerializer

    def post(self, request, *args, **kwargs):
        variant_data = request.data
        attachment_option_data = variant_data.pop('attachment_option', [])
        sensor_option_data = variant_data.pop('sensor_option', [])

        variant_name = variant_data.get('variant_name')
        existing_variant = Variant.objects.filter(variant_name=variant_name).first()

        if existing_variant:
            return Response(
                {"error": "Variant with the same name already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )

        variant_serializer = self.get_serializer(data=variant_data)
        variant_serializer.is_valid(raise_exception=True)
        variant = variant_serializer.save()

        for attachment in attachment_option_data:
            attachment_id = attachment.get('attachment_id')
            existing_attachment = Attachment_or_Sensor_Master.objects.filter(attachment_sensor_id=attachment_id).first()
            if existing_attachment:
                variant_attachment = Variant_or_Attachment_or_Sensor.objects.create(
                    variant=variant,
                    attachment_or_sensor_id=attachment_id
                )
                variant_attachment.save()
            else:
                return Response(
                    {"error": "Attachment  id not  exists."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        for sensor in sensor_option_data:
            sensor_id = sensor.get('sensor_id')
            existing_sensor = Attachment_or_Sensor_Master.objects.filter(attachment_sensor_id=sensor_id).first()
            if existing_sensor:
                variant_sensor = Variant_or_Attachment_or_Sensor.objects.create(
                    variant=variant,
                    attachment_or_sensor_id=sensor_id
                )
                variant_sensor.save()
            else:
                return Response(
                    {"error": "Sensor with the id not exists."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        response = {
            "message": "Variant Added successfully",
            "status": "success",
            "data": variant_serializer.data,
        }
        return Response(response, status=status.HTTP_201_CREATED)


class GetVariantAPIView(generics.RetrieveAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Variant.objects.all()
    serializer_class = VariantSerializer

    def get(self, request, *args, **kwargs):
        # Get the query parameters
        variant_id = request.query_params.get('variant_id')
        variant_status = request.query_params.get('variant_status')
        variant_name = request.query_params.get('variant_name')

        # Filter the queryset based on the provided parameters
        queryset = self.get_queryset()
        if variant_id:
            queryset = queryset.filter(variant_id=variant_id)
        if variant_status:
            queryset = queryset.filter(variant_status=variant_status)
        if variant_name:
            queryset = queryset.filter(variant_name=variant_name)

        # Get the variant objects from the filtered queryset
        variants = list(queryset)
        if not variants:
            return Response({"error": "Variants not found."}, status=status.HTTP_404_NOT_FOUND)

        response_data = []
        for variant in variants:
            attachment_options = Attachment_or_Sensor_Master.objects.filter(
                variant_or_attachment_or_sensor__variant=variant, attachment_or_sensor=1)
            sensor_options = Attachment_or_Sensor_Master.objects.filter(
                variant_or_attachment_or_sensor__variant=variant, attachment_or_sensor=2)

            attachment_data = []
            sensor_data = []

            for attachment in attachment_options:
                attachment_data.append({
                    'attachment_id': attachment.attachment_sensor_id,
                    'attachment_name': attachment.name
                })

            for sensor in sensor_options:
                sensor_data.append({
                    'sensor_id': sensor.attachment_sensor_id,
                    'sensor_name': sensor.name
                })

            response_data = {
                "message": " variant listed successfully",
                "status": "success",
                "data": {
                    'variant_id': variant.pk,
                    'variant_name': variant.variant_name,
                    'variant_description': variant.variant_description,
                    'variant_status': variant.variant_status,
                    'attachment_option': attachment_data,
                    'sensor_option': sensor_data
                }
            }

            # response_data.append(variant_data)

        return Response(response_data, status=status.HTTP_200_OK)


class UpdateVariantAPIView(generics.UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Variant.objects.all()
    serializer_class = VariantSerializer

    def put(self, request, *args, **kwargs):
        variant_id = self.kwargs.get('variant_id')
        variant_data = request.data
        variant_name = variant_data.get('variant_name')
        variant_description = variant_data.get('variant_description')

        variant = get_object_or_404(Variant, variant_id=variant_id)

        if variant_name:
            existing_variant = Variant.objects.filter(variant_name=variant_name).exclude(variant_id=variant_id).first()
            if existing_variant:
                return Response(
                    {"error": "Variant with the same name already exists."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            variant.variant_name = variant_name

        if variant_description:
            variant.variant_description = variant_description

        variant.save()

        attachment_option = variant_data.get('attachment_option', [])
        sensor_option = variant_data.get('sensor_option', [])
        attachment_data =[]
        with transaction.atomic():
            # Update attachment options
            for attachment in attachment_option:
                attachment_id = attachment.get('attachment_id')
                attachment_name = attachment.get('attachment_name')
                attachment_data.append(attachment_id)
                attachment_data.append(attachment_name)
                try:
                    variant_attachment = Variant_or_Attachment_or_Sensor.objects.get(
                        variant=variant, attachment_or_sensor_id=attachment_id
                    )
                    variant_attachment.attachment_or_sensor.name = attachment_name
                    variant_attachment.attachment_or_sensor.save()
                except Variant_or_Attachment_or_Sensor.DoesNotExist:
                    Attachment_or_Sensor_Master.objects.create(
                        variant=variant,
                        attachment_or_sensor_id=attachment_id,
                        name=attachment_name
                    )

            # Update sensor options
            sensor_data = []
            for sensor in sensor_option:
                sensor_id = sensor.get('sensor_id')
                sensor_name = sensor.get('sensor_name')
                sensor_data.append(sensor_id)
                sensor_data.append(sensor_name)
                try:
                    variant_sensor = Variant_or_Attachment_or_Sensor.objects.get(
                        variant=variant, attachment_or_sensor_id=sensor_id
                    )
                    variant_sensor.attachment_or_sensor.name = sensor_name
                    variant_sensor.attachment_or_sensor.save()
                except Variant_or_Attachment_or_Sensor.DoesNotExist:
                    Attachment_or_Sensor_Master.objects.create(
                        variant=variant,
                        attachment_or_sensor_id=sensor_id,
                        name=sensor_name
                    )
        response = {
            "message": "Variant Updated Successfully",
            "status": "Success",
            "data": {
                    'variant_id': variant.pk,
                    'variant_name': variant.variant_name,
                    'variant_description': variant.variant_description,
                    'variant_status': variant.variant_status,
                    'attachment_option': attachment_data,
                    'sensor_option': sensor_data
                }
            }
        return Response(response, status=status.HTTP_200_OK)


class DeleteVariantAPIView(generics.DestroyAPIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request, variant_id):
        try:
            variant = Variant.objects.get(variant_id=variant_id)
        except Variant.DoesNotExist:
            return Response({'message': 'Variant not found.'}, status=404)

        variant.variant_status = False
        variant.save()
        return Response({'message': 'Variant deleted successfully.'}, status=200)


# Map Management

class AddMapCreateView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        customer_id = request.data.get('customer_id')
        map_name = request.data.get('map_name')
        path_layout = request.data.get('path_layout')
        map_description = request.data.get('map_description')
        map_layout = request.data.get('map_layout')

        # Check if the map_name already exists
        if Map.objects.filter(map_name=map_name).exists():
            return Response({"error": "Map with this name already exists."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            customer = Customer.objects.get(id=customer_id)

            if not customer.customer_status:
                return Response({"error": "Cannot add an inactive customer."},
                                status=status.HTTP_400_BAD_REQUEST)
        except Customer.DoesNotExist:
            return Response({"error": "Customer not found."}, status=status.HTTP_404_NOT_FOUND)

        # Create the Map object and associate it with the Customer instance
        map_obj = Map.objects.create(map_name=map_name, map_layout=map_layout, map_description=map_description,
                                     path_layout=path_layout, customer=customer, created_by=request.user.id)
        serializer = MapSerializer(map_obj)
        response = {
            "message": "Map Added successfully",
            "data": serializer.data,
        }
        return Response(response, status=status.HTTP_201_CREATED)


class GetMapListAPIView(generics.ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = MapSerializer

    def get(self, request):
        map_id = request.query_params.get("map_id")
        map_name = request.query_params.get('map_name')
        customer_id = request.query_params.get('customer_id')
        map_status = request.query_params.get('map_status')

        maps = Map.objects.all()

        if map_id:
            maps = maps.filter(id=map_id)
        if map_name:
            maps = maps.filter(map_name=map_name)
        if customer_id:
            # Use the correct related field name for the customer_id filter
            maps = maps.filter(customer_id=customer_id)
        if map_status:
            maps = maps.filter(map_status=map_status)

        if not maps.exists():
            return Response({"error": "No maps found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = MapSerializer(maps, many=True)
        response = {
            "message": "Get Map Details Successfully",
            "data": serializer.data,
        }
        return Response(response)


class UpdateMapAPIView(generics.UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Map.objects.all()
    serializer_class = MapSerializer
    lookup_field = 'id'

    def put(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        # Check if the customer_id is provided in the request data
        customer_id = request.data.get('customer_id')
        if customer_id is not None:
            # Check if the provided customer_id exists in the Customer table
            try:
                customer = Customer.objects.get(id=customer_id)
            except Customer.DoesNotExist:
                return Response({"error": "Customer not found."}, status=status.HTTP_404_NOT_FOUND)

            # Check if the customer_status is not False
            if not customer.customer_status:
                return Response({"error": "Cannot update with an inactive customer."},
                                status=status.HTTP_400_BAD_REQUEST)

            instance.customer = customer

        self.perform_update(serializer)

        response = {
            "message": "Map Details Updated Successfully",
            "data": serializer.data
        }
        return Response(response)


class DeleteMapAPIView(generics.DestroyAPIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request, id):
        try:
            map = Map.objects.get(id=id)
        except Map.DoesNotExist:
            return Response({'message': 'Map not found.'}, status=404)

        map.map_status = False
        map.save()
        return Response({'message': 'Map deleted successfully.'}, status=200)


# Deployment Management
class AddDeploymentCreateView(generics.CreateAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Deployment.objects.all()
    serializer_class = DeploymentSerializer

    def validate_map_data(self, map_data):
        map = map_data.get('list_of_maps_attached')


        if not map_id or not isinstance(map_id, int):
            raise DRFValidationError("Invalid 'map_id'. It should be an integer.")

        try:
            map_instance = Map.objects.get(id=map_id)
        except Map.DoesNotExist:
            raise DRFValidationError("Map with the provided 'map_id' and does not exist.")

        return map_instance

    def post(self, request, *args, **kwargs):
        deployment_data = request.data
        print('==========',deployment_data)
        deployment_name = deployment_data.get('deployment_name')
        list_of_maps_attached_data = deployment_data.get('list_of_maps_attached', [])
        customer_id = deployment_data.get('customer_id')

        existing_deployment = Deployment.objects.filter(deployment_name=deployment_name).first()
        if existing_deployment:
            return Response(
                {"error": "Deployment with the same name already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if customer_id is not None:
            try:
                customer_instance = Customer.objects.get(id=customer_id)
            except Customer.DoesNotExist:
                return Response({"error": "No Customer with the provided ID"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            customer_instance = None

        deployment_instance = Deployment.objects.create(deployment_name=deployment_name, customer=customer_instance)

        attached_maps = []
        for map_id in list_of_maps_attached_data:
            try:
                map_instance = Map.objects.get(id=map_id)
                Deployment_Maps.objects.create(
                    map=map_instance,
                    deployment=deployment_instance,
                )
                attached_maps.append(map_instance.id)
            except Map.DoesNotExist:
                deployment_instance.delete()
                return Response({"error": f"Map with ID {map_id} does not exist."}, status=status.HTTP_400_BAD_REQUEST)

        response_data = {
            "message": "Deployment Added Successfully",
            "data": {
                "id": deployment_instance.id,
                "deployment_name": deployment_instance.deployment_name,
                "customer_id": deployment_instance.customer_id,
                "list_of_maps_attached": attached_maps
            }
        }

        return Response(response_data, status=status.HTTP_201_CREATED)


class UpdateDeploymentView(generics.UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Deployment.objects.all()
    serializer_class = DeploymentSerializer

    def validate_map_data(self, map_id):
        try:
            map_instance = Map.objects.get(id=map_id)
        except Map.DoesNotExist:
            raise DRFValidationError(f"Map with ID {map_id} does not exist.")

        return map_instance

    def put(self, request, *args, **kwargs):
        instance = self.get_object()  # Get the existing Deployment instance
        deployment_data = request.data
        deployment_name = deployment_data.get('deployment_name')
        list_of_maps_attached_data = deployment_data.get('list_of_maps_attached', [])
        customer_id = deployment_data.get('customer_id')

        if deployment_name and deployment_name != instance.deployment_name:
            existing_deployment = Deployment.objects.filter(deployment_name=deployment_name).first()
            if existing_deployment:
                return Response(
                    {"error": "Deployment with the same name already exists."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            instance.deployment_name = deployment_name
            instance.save()

        if customer_id is not None:
            try:
                customer_instance = Customer.objects.get(id=customer_id)
                instance.customer = customer_instance
                instance.save()
            except Customer.DoesNotExist:
                return Response({"error": "No Customer with the provided ID"}, status=status.HTTP_400_BAD_REQUEST)

        # Delete existing Deployment_Maps not in the updated list
        existing_attached_maps = Deployment_Maps.objects.filter(deployment=instance).values_list('map_id', flat=True)
        maps_to_remove = set(existing_attached_maps) - set(list_of_maps_attached_data)
        Deployment_Maps.objects.filter(deployment=instance, map_id__in=maps_to_remove).delete()

        attached_maps = []
        for map_id in list_of_maps_attached_data:
            try:
                map_instance = self.validate_map_data(map_id)
                Deployment_Maps.objects.get_or_create(
                    map=map_instance,
                    deployment=instance,
                )
                attached_maps.append(map_instance.id)
            except DRFValidationError as error:
                return Response({"error": str(error)}, status=status.HTTP_400_BAD_REQUEST)

        response_data = {
            "message": "Deployment Updated Successfully",
            "data": {
                "id": instance.id,
                "deployment_name": instance.deployment_name,
                "customer_id": instance.customer_id,
                "list_of_maps_attached": attached_maps
            }
        }

        return Response(response_data, status=status.HTTP_200_OK)


class GetDeploymentAPIView(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = DeploymentSerializer

    def get_queryset(self):
        queryset = Deployment.objects.all()

        deployment_id = self.request.query_params.get('id')
        deployment_name = self.request.query_params.get('deployment_name')
        deployment_status = self.request.query_params.get('deployment_status')
        customer_id = self.request.query_params.get('customer_id')
        user_id = self.request.query_params.get('user_id')

        if deployment_id:
            queryset = queryset.filter(id=deployment_id)

        if deployment_name:
            queryset = queryset.filter(deployment_name__iexact=deployment_name)

        if deployment_status:
            queryset = queryset.filter(deployment_status__iexact=deployment_status)

        # Filter by customer_id and user_id
        if customer_id:
            queryset = queryset.filter(deployment_maps__customer_id=customer_id)

        if user_id:
            queryset = queryset.filter(deployment_maps__user_id=user_id)

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serialized_data = self.get_serializer(queryset, many=True).data

        response_data = {
            "message": "Deployment Listed Successfully",
            "data": []
        }

        for data in serialized_data:
            deployment_id = data["id"]
            deployment_name = data["deployment_name"]
            deployment_status = data["deployment_status"]
            attached_maps = self.get_attached_maps(deployment_id)
            customer_ids = self.get_customer_ids(deployment_id)
            user_ids = self.get_user_ids(deployment_id)

            response_data["data"].append({
                "id": deployment_id,
                "deployment_name": deployment_name,
                "deployment_status": deployment_status,
                "list_of_maps_attached": attached_maps,
                "customer_id": customer_ids,
                "user_id": user_ids
            })

        return Response(response_data, status=status.HTTP_200_OK)

    def get_attached_maps(self, deployment_id):
        attached_maps = Deployment_Maps.objects.filter(deployment_id=deployment_id)
        serialized_maps = [
            {
                "map_id": deployment_map.map.id,
                "map_name": deployment_map.map.map_name
            }
            for deployment_map in attached_maps
        ]
        return serialized_maps

    def get_customer_ids(self, deployment_id):
        # customer_ids = Deployment_Maps.objects.filter(deployment_id=deployment_id).values_list('customer_id', flat=True)
        customer_ids = Deployment_Maps.objects.filter(deployment_id=deployment_id).values_list( flat=True)

        return list(customer_ids)

    def get_user_ids(self, deployment_id):
        # user_ids = Deployment_Maps.objects.filter(deployment_id=deployment_id).values_list('user_id', flat=True)
        user_ids = Deployment_Maps.objects.filter(deployment_id=deployment_id).values_list( flat=True)

        return list(user_ids)


class DeleteDeploymentAPIView(generics.DestroyAPIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request, id):
        try:
            deployment = Deployment.objects.get(id=id)
        except Deployment.DoesNotExist:
            return Response({'message': 'Deployment not found.'}, status=404)

        deployment.deployment_status = False
        deployment.save()
        return Response({'message': 'Deployment  deleted successfully.'}, status=200)


# Vehicle Management
class AddVehicleAPIView(generics.CreateAPIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        data = request.data
        attachment_options_data = data.get('attachment_option', [])

        vehicle_data = {
            'vehicle_label': data.get('vehicle_label'),
            'endpoint_id': data.get('endpoint_id'),
            'application_id': data.get('application_id'),
            'vehicle_variant': data.get('vehicle_variant'),
            'customer_id': data.get('customer_id'),
        }

        # Check if a vehicle with the same label already exists
        if Vehicle.objects.filter(vehicle_label=vehicle_data['vehicle_label']).exists():
            return Response({"vehicle_label": "A vehicle with this label already exists."},
                            status=status.HTTP_400_BAD_REQUEST)
        if Variant.objects.filter(variant_name=vehicle_data['vehicle_variant']).exists():

            if Customer.objects.filter(id=vehicle_data['customer_id']).exists():

                # Create the vehicle
                vehicle = Vehicle.objects.create(**vehicle_data)
            else:
                return Response({"custom_id": "No Customer or InValid Customer id "}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"vehicle_variant": "No Variant or InValid Vehicle_Variant"},
                            status=status.HTTP_404_NOT_FOUND)

        # Store the attachment options for the response
        response_attachment_options = []

        for option_data in attachment_options_data:
            name = option_data.get('name')
            attachment_sensor_id = option_data.get('attachment_sensor_id')

            # Check if an attachment option with the same name exists
            try:
                attachment_option = Attachment_or_Sensor_Master.objects.get(name=name)
            except Attachment_or_Sensor_Master.DoesNotExist:
                return Response(
                    {"attachment_option": [{"name": f"Attachment option with name '{name}' does not exist."}]},
                    status=status.HTTP_400_BAD_REQUEST)

            # Check if an attachment option with the same attachment_sensor_id exists
            try:
                existing_attachment = Attachment_or_Sensor_Master.objects.get(attachment_sensor_id=attachment_sensor_id)
            except Attachment_or_Sensor_Master.DoesNotExist:
                return Response({"attachment_option": [
                    {"name": f"Attachment option with attachment_sensor_id '{attachment_sensor_id}' does not exist."}]},
                    status=status.HTTP_400_BAD_REQUEST)

            # Create and associate the vehicle attachment with the vehicle
            vehicle_attachment = Vehicle_Attachments.objects.create(vehicle=vehicle,
                                                                    attachment_option=attachment_option)

            # Add the attachment option details to the response list
            response_attachment_options.append({
                "attachment_sensor_id": attachment_option.attachment_sensor_id,
                "name": attachment_option.name,
            })

        # Prepare the complete response
        response_data = {
            "message": "Vehicle Added Successfully",
            "vehicle_id": vehicle.id,
            "vehicle_label": vehicle.vehicle_label,
            "endpoint_id": vehicle.endpoint_id,
            "application_id": vehicle.application_id,
            "vehicle_variant": vehicle.vehicle_variant,
            "customer_id": vehicle.customer_id,
            "attachment_option": response_attachment_options,
        }

        return Response(response_data, status=status.HTTP_201_CREATED)


class UpdateVehicleAPIView(generics.UpdateAPIView):
    permission_classes = (IsAuthenticated,)

    def put(self, request, *args, **kwargs):
        data = request.data
        vehicle_id = kwargs.get('pk')

        try:
            vehicle = Vehicle.objects.get(pk=vehicle_id)
        except Vehicle.DoesNotExist:
            return Response({"detail": "Vehicle not found."}, status=status.HTTP_404_NOT_FOUND)

        attachment_options_data = data.get('attachment_option', [])

        vehicle_data = {
            'vehicle_label': data.get('vehicle_label', vehicle.vehicle_label),
            'endpoint_id': data.get('endpoint_id', vehicle.endpoint_id),
            'application_id': data.get('application_id', vehicle.application_id),
            'vehicle_variant': data.get('vehicle_variant', vehicle.vehicle_variant),
            'customer_id': data.get('customer_id', vehicle.customer_id),
        }

        # Check if a vehicle with the same label already exists
        if Vehicle.objects.exclude(pk=vehicle_id).filter(vehicle_label=vehicle_data['vehicle_label']).exists():
            return Response({"vehicle_label": "A vehicle with this label already exists."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Update the vehicle
        for key, value in vehicle_data.items():
            setattr(vehicle, key, value)
        vehicle.save()

        # Store the attachment options for the response
        response_attachment_options = []

        for option_data in attachment_options_data:
            name = option_data.get('name')
            attachment_sensor_id = option_data.get('attachment_sensor_id')

            # Check if an attachment option with the same name exists
            try:
                attachment_option = Attachment_or_Sensor_Master.objects.get(name=name)
            except Attachment_or_Sensor_Master.DoesNotExist:
                return Response(
                    {"attachment_option": [{"name": f"Attachment option with name '{name}' does not exist."}]},
                    status=status.HTTP_400_BAD_REQUEST)

            # Check if an attachment option with the same attachment_sensor_id exists
            try:
                existing_attachment = Attachment_or_Sensor_Master.objects.get(attachment_sensor_id=attachment_sensor_id)
            except Attachment_or_Sensor_Master.DoesNotExist:
                return Response({"attachment_option": [
                    {"name": f"Attachment option with attachment_sensor_id '{attachment_sensor_id}' does not exist."}]},
                    status=status.HTTP_400_BAD_REQUEST)

            # Create and associate the vehicle attachment with the vehicle
            vehicle_attachment = Vehicle_Attachments.objects.create(vehicle=vehicle,
                                                                    attachment_option=attachment_option)

            # Add the attachment option details to the response list
            response_attachment_options.append({
                "attachment_sensor_id": attachment_option.attachment_sensor_id,
                "name": attachment_option.name,
            })

        # Prepare the complete response
        response_data = {
            "message": "Vehicle Updated successfully",
            "vehicle_id": vehicle.id,
            "vehicle_label": vehicle.vehicle_label,
            "endpoint_id": vehicle.endpoint_id,
            "application_id": vehicle.application_id,
            "vehicle_variant": vehicle.vehicle_variant,
            "customer_id": vehicle.customer_id,
            "attachment_option": response_attachment_options,
        }

        return Response(response_data, status=status.HTTP_200_OK)


class GetVehicleAPIView(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = VehicleSerializer

    def get_queryset(self):
        queryset = Vehicle.objects.all()

        vehicle_id = self.request.query_params.get('vehicle_id')
        vehicle_label = self.request.query_params.get('vehicle_label')
        vehicle_status = self.request.query_params.get('vehicle_status')
        customer_id = self.request.query_params.get('customer_id')

        if vehicle_id:
            queryset = queryset.filter(id=vehicle_id)

        if vehicle_label:
            queryset = queryset.filter(vehicle_label__iexact=vehicle_label)

        if vehicle_status:
            queryset = queryset.filter(vehicle_status__iexact=vehicle_status)

        if customer_id:
            queryset = queryset.filter(customer_id=customer_id)

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serialized_data = self.get_serializer(queryset, many=True).data

        response_data = {
            "message": "Vehicle Listed Successfully",
            "data": []
        }

        for data in serialized_data:
            vehicle_id = data["id"]
            vehicle_label = data["vehicle_label"]
            vehicle_status = data["vehicle_status"]
            customer_id = data["customer"]
            attachment_option = self.get_attachementoptions(vehicle_id)

            response_data["data"].append({
                "id": vehicle_id,
                "vehicle_label": vehicle_label,
                "vehicle_status": vehicle_status,
                "customer_id": customer_id,
                "attachment_option": attachment_option
            })

        return Response(response_data, status=status.HTTP_200_OK)

    def get_attachementoptions(self, vehicle_id):
        attachment_option = Vehicle_Attachments.objects.filter(id=vehicle_id)
        serialized_data = [
            {
                "attachment_sensor_id": attachments.attachment_option.attachment_sensor_id,
                "name": attachments.attachment_option.name
            }
            for attachments in attachment_option
        ]
        return serialized_data


class DeleteVehicleAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Vehicle.objects.all()
    serializer_class = VehicleSerializer
    lookup_url_kwarg = 'id'

    def delete(self, request, id):
        try:
            vehicle = Vehicle.objects.get(id=id)
        except Vehicle.DoesNotExist:
            return Response({'message': 'Vehicle  not found.'}, status=404)

        vehicle.vehicle_status = False
        vehicle.save()
        return Response({'message': 'Vehicle  deleted successfully.'}, status=200)


# Fleet Management
class AddFleetAPIView(generics.CreateAPIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        fleet_data = request.data
        fleet_name = fleet_data.get('name')
        deployment_id = fleet_data.get('deployment_id')
        vehicles_data = fleet_data.get('vehicles', [])
        customer_id = fleet_data.get('customer_id')

        # Validate deployment
        try:
            deployment = Deployment.objects.get(id=deployment_id)
        except Deployment.DoesNotExist:
            return Response({"deployment_id": "Invalid Deployment ID."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate customer
        try:
            customer_instance = Customer.objects.get(id=customer_id)
        except Customer.DoesNotExist:
            return Response({"customer_id": f"Customer with ID {customer_id} does not exist."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Ensure fleet_name is not None or empty
        if not fleet_name:
            return Response({"fleet_name": "Fleet name cannot be empty."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if fleet with the same name exists
        # fleet = Fleet.objects.filter(name=fleet_name).first()
        if Fleet.objects.filter(name=fleet_name):
            return Response({"fleet_name": "Fleet name already exsist."}, status=status.HTTP_208_ALREADY_REPORTED)

        if Fleet.objects.filter(name=fleet_name):
            # If fleet exists, update it
            fleet.name = fleet_name  # You can assign other fields as well
        else:
            # If fleet doesn't exist, create a new one
            fleet = Fleet(name=fleet_name, customer=customer_instance)  # Assign customer_id

        fleet.save()  # Save the fleet

        # Handle vehicles
        response_attached_vehicles = []
        for vehicle in vehicles_data:
            vehicle_id = vehicle.get('id')
            try:
                vehicle_instance = Vehicle.objects.get(id=vehicle_id)
            except Vehicle.DoesNotExist:
                return Response({"vehicles": f"Vehicle with ID {vehicle_id} does not exist."},
                                status=status.HTTP_400_BAD_REQUEST)

            Fleet_Vehicle_Deployment.objects.create(fleet=fleet, vehicle=vehicle_instance, deployment=deployment)

            response_attached_vehicles.append({
                "vehicle_id": vehicle_instance.id,
                "vehicle_label": vehicle_instance.vehicle_label,
            })

        response_data = {
            "message": "Fleet Added Successfully",
            "status":"success",
            "data": {
                "fleet_name": fleet.name,
                "customer_id": fleet.customer_id,
                "status": fleet.status
                },
            # Include any other fields you want to return
            "attached_vehicles": response_attached_vehicles,
        }
        return Response(response_data, status=status.HTTP_201_CREATED)


from django.core.exceptions import ObjectDoesNotExist

class UpdateFleetAPIView(generics.UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Fleet.objects.all()
    serializer_class = FleetSerializer

    def put(self, request, *args, **kwargs):
        fleet_data = request.data
        fleet_name = fleet_data.get('fleet_name')
        deployment_id = fleet_data.get('deployment_id')
        vehicles_data = fleet_data.get('vehicles', [])
        customer_id = fleet_data.get('customer_id')

        try:
            fleet = Fleet.objects.get(name=fleet_name)
        except ObjectDoesNotExist:
            return Response({"fleet_name": f"Fleet with name {fleet_name} does not exist."},
                            status=status.HTTP_400_BAD_REQUEST)

        fleet_serializer = self.get_serializer(fleet, data=fleet_data)

        try:
            deployment = Deployment.objects.get(id=deployment_id)
        except Deployment.DoesNotExist:
            return Response({"deployment_id": "Invalid Deployment ID."},
                            status=status.HTTP_400_BAD_REQUEST)

        fleet_serializer.is_valid(raise_exception=True)
        fleet = fleet_serializer.save()

        try:
            customer_instance = Customer.objects.get(id=customer_id)
        except Customer.DoesNotExist:
            return Response({"customer_id": f"Customer with ID {customer_id} does not exist."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Continue with the rest of your code for vehicle handling
        # ...

        fleet_response_data = fleet_serializer.data

        response_data = {
            "message": "Fleet Updated Successfully",
            "fleet_data": fleet_response_data,
            "attached_vehicles": response_attached_vehicles,
            "customer_id": customer_id,
        }
        return Response(response_data, status=status.HTTP_200_OK)



class GetFleetAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = FleetSerializer

    def get(self, request, *args, **kwargs):
        fleet_id = request.query_params.get('fleet_id')
        fleet_name = request.query_params.get('fleet_name')
        fleet_status = request.query_params.get('fleet_status')
        customer_id = request.query_params.get('customer_id')
        user_id = request.query_params.get('user_id')

        try:
            fleet_instance = None

            if fleet_id:
                fleet_instance = Fleet.objects.get(id=fleet_id)
            elif fleet_name:
                fleet_instance = Fleet.objects.get(name=fleet_name)
            elif fleet_status:
                fleet_instance = Fleet.objects.get(status=fleet_status)

            fleet_deployments = Fleet_Vehicle_Deployment.objects.filter(fleet=fleet_instance)

            if user_id:
                user_deployments = fleet_deployments.filter(user=user_id)
            else:
                user_deployments = []

            if customer_id:
                customer_deployments = fleet_deployments.filter(customer=customer_id)
            else:
                customer_deployments = []

            # Gather relevant data for the response
            response_data = {
                "fleet_data": self.serializer_class(fleet_instance).data,
                "user_data": [self.get_user_data(deployment) for deployment in user_deployments],
                "customer_data": [self.get_customer_data(deployment) for deployment in customer_deployments]
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Fleet.DoesNotExist:
            return Response({"detail": "Fleet not found."}, status=status.HTTP_404_NOT_FOUND)

    def get_user_data(self, deployment):
        return {
            "id": deployment.user.id,
            # Add other user-related fields here
        }

    def get_customer_data(self, deployment):
        return {
            "id": deployment.customer.id,
            # Add other customer-related fields here
        }


class DeleteFleetAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Fleet.objects.all()
    serializer_class = FleetSerializer
    lookup_url_kwarg = 'id'

    def delete(self, request, id):
        try:
            fleet = Fleet.objects.get(id=id)
        except Fleet.DoesNotExist:
            return Response({'message': 'Fleet  not found.'}, status=404)

        fleet.status = False
        fleet.save()
        return Response({'message': 'Fleet  deleted successfully.'}, status=200)


# Group Management
class AddGroupAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GroupSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        group_name = data.get('name')
        vehicles_data = data.get('vehicles', [])
        fleets_data = data.get('fleets', [])
        deployments_data = data.get('deployments', [])
        customer_data = data.get('customers', [])

        # Check if a group with the same name already exists
        if UserGroup.objects.filter(name=group_name).exists():
            return Response({'message': 'Group with the same name already exists'},
                            status=status.HTTP_208_ALREADY_REPORTED)

        # Validate and get the actual Deployment objects based on provided IDs
        for deployment in deployments_data:
            deployment_id = deployment.get('id')
            deployment_name = deployment.get('name')
            try:
                deployment_obj = Deployment.objects.get(id=deployment_id, deployment_name=deployment_name)
            except Deployment.DoesNotExist:
                return Response({"message": "Invalid Deployment ID or Name."},
                                status=status.HTTP_400_BAD_REQUEST)

        # Validate and get the actual Customer objects based on provided IDs
        for customer in customer_data:
            customer_id = customer.get('id')
            customer_name = customer.get('name')
            try:
                customer_obj = Customer.objects.get(id=customer_id, customer_name=customer_name)
            except Customer.DoesNotExist:
                return Response({"message": "Invalid Customer ID or Name."},
                                status=status.HTTP_400_BAD_REQUEST)

        # Validate and get the actual Vehicle objects based on provided IDs
        for vehicle_data in vehicles_data:
            vehicle_id = vehicle_data.get('id')
            vehicle_name = vehicle_data.get('name')
            try:
                vehicle_obj = Vehicle.objects.get(id=vehicle_id, vehicle_label=vehicle_name)
            except Vehicle.DoesNotExist:
                return Response({"message": f"Vehicle with ID or Name does not exist."},
                                status=status.HTTP_400_BAD_REQUEST)

        # Validate and get the actual Fleet objects based on provided IDs
        for fleet in fleets_data:
            fleet_id = fleet.get('id')
            fleet_name = fleet.get('name')
            try:
                fleet_obj = Fleet.objects.get(id=fleet_id, name=fleet_name)
            except Fleet.DoesNotExist:
                return Response({"message": f"Fleet with ID or Name does not exist."},
                                status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        group = serializer.save()

        # Store the response datas
        group_res_data = []
        vehicles_attached = []
        customers_attached = []
        fleets_attached = []
        deployments_attached = []

        Group_Deployment_Vehicle_Fleet_Customer.objects.create(group=group,
                                                               fleet=fleet_obj,
                                                               vehicle=vehicle_obj,
                                                               deployment=deployment_obj,
                                                               customer=customer_obj
                                                               )
        # Prepare the response for the attached vehicle,customr,fleets,deployments
        group_res_data.append({
            "group_id": group.id,
            "group_name": group.name,
            "group_status": group.status
        }),
        vehicles_attached.append({
            "vehicle_id": vehicle_obj.id,
            "vehicle_label": vehicle_obj.vehicle_label
        }),

        customers_attached.append({
            "customer_id": customer_obj.id,
            "customer_name": customer_obj.customer_name
        }),
        fleets_attached.append({
            "fleet_id": fleet_obj.id,
            "fleet_name": fleet_obj.name

        }),
        deployments_attached.append({
            "deployment_id": deployment_obj.id,
            "deployment_name": deployment_obj.deployment_name
        })

        response_data = {
            "message": "Group added successfully.",
            "group_data": group_res_data,
            "attached_vehicles": vehicles_attached,
            "attached_customers": customers_attached,
            "attached_deployments": deployments_attached,
            "attached_fleets": fleets_attached,
        }
        return Response(response_data, status=status.HTTP_201_CREATED)


class UpdateGroupAPIView(generics.RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GroupSerializer

    def get_object(self):
        group_id = self.kwargs.get('id')
        try:
            group = UserGroup.objects.get(id=group_id)
            return group
        except UserGroup.DoesNotExist:
            return Response({"message": "Group does not exist"}, status=status.HTTP_404_NOT_FOUND)

    def update(self, request, *args, **kwargs):
        group = self.get_object()
        data = request.data
        group_name = data.get('name')
        vehicles_data = data.get('vehicles', [])
        deployments_data = data.get('deployments', [])
        customer_data = data.get('customers', [])
        fleets_data = data.get('fleets', [])

        # Check if a group with the same name already exists (excluding the current group)
        if group_name and group_name.lower() != group.name.lower() and UserGroup.objects.filter(
                name__iexact=group_name).exists():
            return Response({'message': 'Group with the same name already exists'},
                            status=status.HTTP_208_ALREADY_REPORTED)

        # Validate and get the actual Deployment objects based on provided IDs
        deployments_attached = []
        for deployment in deployments_data:
            deployment_id = deployment.get('id')
            deployment_name = deployment.get('name')
            try:
                deployment_obj = Deployment.objects.get(id=deployment_id, deployment_name=deployment_name)
            except Deployment.DoesNotExist:
                return Response({"message": "Invalid Deployment ID or Name."},
                                status=status.HTTP_400_BAD_REQUEST)
            deployments_attached.append({
                "deployment_id": deployment_obj.id,
                "deployment_name": deployment_obj.deployment_name
            })

        # Validate and get the actual Customer objects based on provided IDs
        customers_attached = []
        for customer in customer_data:
            customer_id = customer.get('id')
            customer_name = customer.get('name')
            try:
                customer_obj = Customer.objects.get(id=customer_id, customer_name=customer_name)
            except Customer.DoesNotExist:
                return Response({"message": "Invalid Customer ID or Name."},
                                status=status.HTTP_400_BAD_REQUEST)
            customers_attached.append({
                "customer_id": customer_obj.id,
                "customer_name": customer_obj.customer_name
            })

        # Validate and get the actual Vehicle objects based on provided IDs
        vehicles_attached = []
        for vehicle_data in vehicles_data:
            vehicle_id = vehicle_data.get('id')
            vehicle_name = vehicle_data.get('name')
            try:
                vehicle_obj = Vehicle.objects.get(id=vehicle_id, vehicle_label=vehicle_name)
            except Vehicle.DoesNotExist:
                return Response({"message": f"Vehicle with ID or Name does not exist."},
                                status=status.HTTP_400_BAD_REQUEST)
            vehicles_attached.append({
                "vehicle_id": vehicle_obj.id,
                "vehicle_label": vehicle_obj.vehicle_label
            })

        # Validate and get the actual Fleet objects based on provided IDs
        fleets_attached = []
        for fleet_data in fleets_data:
            fleet_id = fleet_data.get('id')
            fleet_name = fleet_data.get('name')
            try:
                fleet_obj = Fleet.objects.get(id=fleet_id, name=fleet_name)
            except Fleet.DoesNotExist:
                return Response({"message": f"Fleet with ID or Name does not exist."},
                                status=status.HTTP_400_BAD_REQUEST)
            fleets_attached.append({
                "fleet_id": fleet_obj.id,
                "fleet_name": fleet_obj.name
            })

        serializer = self.get_serializer(group, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        updated_group = serializer.save()

        # Clear the existing related objects for the group
        Group_Deployment_Vehicle_Fleet_Customer.objects.filter(group=updated_group).delete()

        # Store the updated response data
        group_res_data = []

        fleets_attached = []
        for fleet_data in fleets_attached:
            fleet_id = fleet_data['fleet_id']
            fleet_name = fleet_data['fleet_name']
            fleet_obj = Fleet.objects.get(id=fleet_id, name=fleet_name)
        fleets_attached.append({
                "fleet_id": fleet_obj.id,
                "fleet_name": fleet_obj.name
        }),
        group_res_data.append({
                "group_id": group.id,
                "group_name": group.name,
                "group_status": group.status
        })

        response_data = {
            "message": "Group updated successfully.",
            "group_data": group_res_data,
            "attached_vehicles": vehicles_attached,
            "attached_customers": customers_attached,
            "attached_deployments": deployments_attached,
            "attached_fleets": fleets_attached
        }
        return Response(response_data, status=status.HTTP_200_OK)


class GetGroupAPIView(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GroupSerializer

    def get(self, request, *args, **kwargs):
        group_id = request.query_params.get('id')
        group_name = request.query_params.get('group_name')
        group_status = request.query_params.get('group_status')
        customer_id = request.query_params.get('customer_id')

        if group_id is None and group_name is None and group_status is None and customer_id is None:
            return Response(
                {"message": "At least one of group_id, group_name, or group_status, customer_id must be provided."},
                status=status.HTTP_400_BAD_REQUEST)

        try:
            if group_id:
                group_instance = UserGroup.objects.get(id=group_id)
            elif group_name:
                group_instance = UserGroup.objects.get(name=group_name)
            elif group_status:
                group_instance = UserGroup.objects.get(status=group_status)
            elif customer_id:
                group_instance = UserGroup.objects.get(id=customer_id)

            group_data = Group_Deployment_Vehicle_Fleet_Customer.objects.select_related(
                'group', 'deployment', 'vehicle', 'fleet', 'customer'
            ).get(group=group_instance)

            # Serialize the data
            attached_vehicle_data = {
                                        "id": group_data.vehicle.id,
                                        "vehicle_label": group_data.vehicle.vehicle_label,
                                        # Add any other fields you want to include for each attached vehicle
                                    },
            attached_deployment_data = {
                                           "id": group_data.deployment.id,
                                           "deployment_name": group_data.deployment.deployment_name,
                                       },
            attached_fleet_data = {
                                      "id": group_data.fleet.id,
                                      "fleet_name": group_data.fleet.name,
                                  },
            attached_customer_data = {
                "id": group_data.customer.id,
                "customer_name": group_data.customer.customer_name,
            }

            group_data = {
                "message": "Group Data Listing Successfully",
                "group_data": GroupSerializer(group_instance).data,
                "attached_vehicle": attached_vehicle_data,
                "fleet_data": attached_fleet_data,
                "deployment_data": attached_deployment_data,
                "customer_data": attached_customer_data,
            }

            return Response(group_data, status=status.HTTP_200_OK)
        except UserGroup.DoesNotExist:
            return Response({"message": "Group not found."},
                            status=status.HTTP_404_NOT_FOUND)
        except Group_Deployment_Vehicle_Fleet_Customer.DoesNotExist:
            return Response({"message": "Group data not found."},
                            status=status.HTTP_404_NOT_FOUND)


class DeleteGroupAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = UserGroup.objects.all()
    serializer_class = GroupSerializer
    lookup_url_kwarg = 'id'

    def delete(self, request, id):
        try:
            group = UserGroup.objects.get(id=id)
        except UserGroup.DoesNotExist:
            return Response({'message': 'Group  not found.'}, status=404)

        group.status = False
        group.save()
        return Response({'message': 'Group  deleted successfully.'}, status=200)


class AddActionAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ActionSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        action_name = data.get('name')

        if Action.objects.filter(name=action_name).exists():
            return Response({'message': 'Action name already exists.'}, status.HTTP_208_ALREADY_REPORTED)

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        if serializer.is_valid():
            serializer.save()
            response_data = {
                'message': 'Action added successfully',
                'status': 'success',
                'data': serializer.data
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateActionAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ActionSerializer

    def put(self, request, id, *args, **kwargs):
        try:
            action = Action.objects.get(id=id)
        except Action.DoesNotExist:
            return Response({"message": "Action not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(action, data=request.data)

        if serializer.is_valid():
            # Check if another action with the same name exists and has a different ID
            action_name = serializer.validated_data.get('name')
            if Action.objects.filter(name=action_name).exclude(id=id).exists():
                return Response({"message": "Action name already exists with another ID."},
                                status=status.HTTP_400_BAD_REQUEST)

            serializer.save()
            response_data = {
                'message': 'Action Updated successfully',
                'status': 'success',
                'data': serializer.data
            }
            return Response(response_data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetActionAPIView(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ActionSerializer

    def get(self, request, *args, **kwargs):
        action_id = request.query_params.get('id')
        action_name = request.query_params.get('name')
        action_status = request.query_params.get('status')

        if action_id is None and action_name is None and action_status is None:
            return Response({"message": "At least one of id, name, or status must be provided."},
                            status=status.HTTP_400_BAD_REQUEST)

        queryset = Action.objects.all()

        if action_id:
            queryset = queryset.filter(id=action_id)
        if action_name:
            queryset = queryset.filter(name__iexact=action_name)
        if action_status:
            queryset = queryset.filter(status=action_status)

        if not queryset.exists():
            return Response({"message": "Action data not found."},
                            status=status.HTTP_404_NOT_FOUND)

        action_data = {
            "message": "Action Data Listing Successfully",
            "action_data": ActionSerializer(queryset, many=True).data,
        }

        return Response(action_data, status=status.HTTP_200_OK)


class DeleteActionAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Action.objects.all()
    serializer_class = ActionSerializer
    lookup_url_kwarg = 'id'

    def delete(self, request, id):
        try:
            action = Action.objects.get(id=id)
        except Action.DoesNotExist:
            return Response({'message': 'Action  not found.'}, status=404)

        action.status = False
        action.save()
        return Response({'message': 'Action  deleted successfully.'}, status=200)


# Missing Management
class AddMissionAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = MissionSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        mission_name = data.get('name')
        map_data = data.get('maps', [])
        fleets_data = data.get('fleets', [])
        deployments_data = data.get('deployments', [])
        action_data = data.get('actions', [])

        # Check if a mission with the same name already exists
        if Mission.objects.filter(name=mission_name).exists():
            return Response({'message': 'Mission with the same name already exists'},
                            status=status.HTTP_208_ALREADY_REPORTED)

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        mission = serializer.save()

        # Store the response data lists
        mission_data = []
        maps_attached = []
        fleets_attached = []
        deployments_attached = []
        action_attached = []

        # Loop through the maps data and create related objects
        for map_item in map_data:
            map_id = map_item.get('id')
            map_name = map_item.get('name')
            try:
                map_obj = Map.objects.get(id=map_id, map_name=map_name)
            except Map.DoesNotExist:
                return Response({"message": f"Map with ID or Name does not exist."},
                                status=status.HTTP_400_BAD_REQUEST)
            maps_attached.append({
                "map_id": map_obj.id,
                "map_name": map_obj.map_name,
            })

            # Loop through the fleets data and create related objects
        for fleet_item in fleets_data:
            fleet_id = fleet_item.get('id')
            fleet_name = fleet_item.get('name')
            try:
                fleet_obj = Fleet.objects.get(id=fleet_id, name=fleet_name)
            except Fleet.DoesNotExist:
                return Response({"message": f"Fleet with ID or Name does not exist."},
                                status=status.HTTP_400_BAD_REQUEST)
            fleets_attached.append({
                "fleet_id": fleet_obj.id,
                "fleet_name": fleet_obj.name,
            })

        # Loop through the deployments data and create related objects
        for deployment_item in deployments_data:
            deployment_id = deployment_item.get('id')
            deployment_name = deployment_item.get('name')
            try:
                deployment_obj = Deployment.objects.get(id=deployment_id, deployment_name=deployment_name)
            except Deployment.DoesNotExist:
                return Response({"message": "Invalid Deployment ID or Name."},
                                status=status.HTTP_400_BAD_REQUEST)
            deployments_attached.append({
                "deployment_id": deployment_obj.id,
                "deployment_name": deployment_obj.deployment_name,
            })
            for action in action_data:
                id = action.get('id')
                name = action.get('name')
                try:
                    action_obj = Action.objects.get(id=id, name=name)
                except Action.DoesNotExist:
                    return Response({"message": "Invalid Action ID or Name."},
                                    status=status.HTTP_400_BAD_REQUEST)
                Mission_Fleet_Map_Deployment_Action.objects.create(mission=mission, action=action_obj, map=map_obj,
                                                                   deployment=deployment_obj, fleet=fleet_obj)
                action_attached.append({
                    "action_id": action_obj.id,
                    "action_name": action_obj.name,
                })

        # Prepare the response data
        mission_data.append({
            "mission_id": mission.id,
            "mission_name": mission.name,
            "mission_status": mission.status,
        })

        response_data = {
            "message": "Mission added successfully.",
            "mission_data": mission_data,
            "attached_maps": maps_attached,
            "attached_deployments": deployments_attached,
            "attached_fleets": fleets_attached,
            "attached_actions": action_attached,
        }
        return Response(response_data, status=status.HTTP_201_CREATED)


class UpdateMissionAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = MissionSerializer

    def get_object(self, id):
        try:
            return Mission.objects.get(id=id)
        except Mission.DoesNotExist:
            return None

    def put(self, request, id, *args, **kwargs):
        # Check if the mission with the given ID exists
        mission = self.get_object(id)
        if not mission:
            return Response({'message': 'Mission not found'}, status=status.HTTP_404_NOT_FOUND)

        data = request.data
        mission_name = data.get('name')
        map_data = data.get('maps', [])
        fleets_data = data.get('fleets', [])
        deployments_data = data.get('deployments', [])
        action_data = data.get('actions', [])

        # Check if a mission with the same name already exists (excluding the current mission)
        if Mission.objects.filter(name=mission_name).exclude(id=id).exists():
            return Response({'message': 'Mission with the same name already exists'},
                            status=status.HTTP_208_ALREADY_REPORTED)

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)

        # Update the mission object with the new data
        mission.name = mission_name
        # Add any additional fields that you want to update here.

        # Save the updated mission object
        mission.save()

        # Loop through the maps data and update related objects
        for map_item in map_data:
            map_id = map_item.get('id')
            map_name = map_item.get('name')
            try:
                map_obj = Map.objects.get(id=map_id, map_name=map_name)
            except Map.DoesNotExist:
                return Response({"message": f"Map with ID or Name does not exist."},
                                status=status.HTTP_400_BAD_REQUEST)

            # Update the existing map object with any new data
            map_obj.name = map_name
            # Add any additional fields that you want to update here.

            # Save the updated map object
            map_obj.save()

        # Loop through the fleets data and update related objects
        for fleet_item in fleets_data:
            fleet_id = fleet_item.get('id')
            fleet_name = fleet_item.get('name')
            try:
                fleet_obj = Fleet.objects.get(id=fleet_id, name=fleet_name)
            except Fleet.DoesNotExist:
                return Response({"message": f"Fleet with ID or Name does not exist."},
                                status=status.HTTP_400_BAD_REQUEST)

            # Update the existing fleet object with any new data
            fleet_obj.name = fleet_name
            # Add any additional fields that you want to update here.

            # Save the updated fleet object
            fleet_obj.save()

        # Loop through the deployments data and update related objects
        for deployment_item in deployments_data:
            deployment_id = deployment_item.get('id')
            deployment_name = deployment_item.get('name')
            try:
                deployment_obj = Deployment.objects.get(id=deployment_id, deployment_name=deployment_name)
            except Deployment.DoesNotExist:
                return Response({"message": "Invalid Deployment ID or Name."},
                                status=status.HTTP_400_BAD_REQUEST)

            # Update the existing deployment object with any new data
            deployment_obj.name = deployment_name
            # Add any additional fields that you want to update here.

            # Save the updated deployment object
            deployment_obj.save()

        # Loop through the actions data and update related objects
        for action_item in action_data:
            action_id = action_item.get('id')
            action_name = action_item.get('name')
            try:
                action_obj = Action.objects.get(id=action_id, name=action_name)
            except Action.DoesNotExist:
                return Response({"message": "Invalid Action ID or Name."},
                                status=status.HTTP_400_BAD_REQUEST)

            # Update the existing action object with any new data
            action_obj.name = action_name
            # Add any additional fields that you want to update here.

            # Save the updated action object
            action_obj.save()

        # Prepare the response data
        mission_data = {
            "mission_id": mission.id,
            "mission_name": mission.name,
            "mission_status": mission.status,
            # Include any other fields you want to include in the response.
        }

        response_data = {
            "message": "Mission updated successfully.",
            "mission_data": mission_data,
            "attached_maps": map_data,
            "attached_deployments": deployments_data,
            "attached_fleets": fleets_data,
            "attached_actions": action_data,
        }

        return Response(response_data, status=status.HTTP_200_OK)


class GetMissionAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        mission_id = request.query_params.get('id')
        mission_name = request.query_params.get('name')
        mission_status = request.query_params.get('status')

        if mission_id is None and mission_name is None and mission_status is None:
            return Response(
                {"message": "At least one of mission_id, mission_name, or mission_status must be provided."},
                status=status.HTTP_400_BAD_REQUEST)

        try:
            mission_queryset = Mission_Fleet_Map_Deployment_Action.objects.select_related(
                'mission', 'deployment', 'map', 'fleet', 'action'
            )

            if mission_id:
                mission_instance = mission_queryset.filter(id=mission_id).first()
            elif mission_name:
                mission_instance = mission_queryset.filter(name=mission_name).first()
            elif mission_status:
                mission_queryset = mission_queryset.filter(
                    mission__status=mission_status
                )
                mission_instance = mission_queryset.first()

            if mission_instance is None:
                return Response({"message": "Mission not found."},
                                status=status.HTTP_404_NOT_FOUND)

            # Serialize the data
            attached_map_data = MapSerializer(mission_instance.map).data
            attached_deployment_data = DeploymentSerializer(mission_instance.deployment).data
            attached_fleet_data = FleetSerializer(mission_instance.fleet).data
            attached_action_data = ActionSerializer(mission_instance.action).data

            mission_data = {
                "message": "Mission Data Listing Successfully",
                "mission_data": MissionSerializer(mission_instance.mission).data,
                "attached_map": attached_map_data,
                "fleet_data": attached_fleet_data,
                "deployment_data": attached_deployment_data,
                "action_data": attached_action_data,
            }

            return Response(mission_data, status=status.HTTP_200_OK)
        except Mission_Fleet_Map_Deployment_Action.MultipleObjectsReturned:
            return Response({"message": "Multiple missions with the provided query parameters."},
                            status=status.HTTP_400_BAD_REQUEST)


class DeleteMissionAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = Mission.objects.all()
    serializer_class = MissionSerializer
    lookup_url_kwarg = 'id'

    def delete(self, request, id):
        try:
            mission = Mission.objects.get(id=id)
        except Mission.DoesNotExist:
            return Response({'message': 'Mission  not found.'}, status=404)

        mission.status = False
        mission.save()
        return Response({'message': 'Mission  deleted successfully.'}, status=200)

from django.db.models import Q

# Dashboard Management
class DashBoardAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = request.user
        uid = user.id
        uname = user.username
        user_role = user.role

        if user.is_authenticated:   # True

            if user.is_superuser:
                customer_count = Customer.objects.count()

                user_count = User.objects.exclude(is_superuser=1).count()

                fleet_count = Fleet.objects.count()

                deployment_count = Deployment.objects.count()

                vehicle_count = Vehicle.objects.count()

                group_count = UserGroup.objects.count()

                total_count_data = {
                    "customer_count": customer_count,
                    "user_count": user_count,
                    "deployment_count": deployment_count,
                    "fleet_count": fleet_count,
                    "vehicle_count": vehicle_count,
                    "group_count": group_count,
                }
                return Response(total_count_data, status=200)

            elif user.trizlabz_user:  # Check if the user is a trizlab_user

                userlogged = Customer_User.objects.filter(user=uid)
                for usr in userlogged:
                    customerdata = usr.customer_id

                customer_count = Customer_User.objects.filter(user=uid).count()

                user_count = Customer_User.objects.filter(user=uid).count()

                fleet_count = Fleet.objects.filter(customer=customerdata).count()

                deployment_count = Deployment.objects.filter(customer=customerdata).count()

                vehicle_count = Vehicle.objects.filter(customer=customerdata).count()

                group_count = User.objects.filter(id=uid).count()

                total_count_data = {
                    "customer_count": customer_count,
                    "user_count": user_count,
                    "deployment_count": deployment_count,
                    "fleet_count": fleet_count,
                    "vehicle_count": vehicle_count,
                    "group_count": group_count,
                }
                return Response(total_count_data, status=200)

            else:
                userlogged=Customer_User.objects.filter(user=uid)
                for usr in userlogged:
                    customerdata=usr.customer_id

                customer_count = Customer_User.objects.filter(user=uid).count()

                user_count = Customer_User.objects.filter(user=uid).count()

                fleet_count = Fleet.objects.filter(customer=customerdata).count()

                deployment_count = Deployment.objects.filter(customer=customerdata).count()

                vehicle_count = Vehicle.objects.filter(customer=customerdata).count()

                group_count = User.objects.filter(id=uid).count()

                related_count_data = {
                    "customer_count": customer_count if hasattr(user, 'customer') else 0,
                    "user_count": user_count,
                    "deployment_count": deployment_count,
                    "fleet_count": fleet_count,
                    "vehicle_count": vehicle_count,
                    "group_count": group_count,
                }
                return Response(related_count_data, status=200)
            
        else:
            return Response({"error": "User not authenticated"}, status=401)
