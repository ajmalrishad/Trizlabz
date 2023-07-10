from django.contrib.auth import logout
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, OutstandingToken

from .models import User, Role, Customer, Variant, Attachment_or_Sensor_Master, Variant_or_Attachment_or_Sensor
from .serializers import RegisterSerializer, LoginSerializer, GetUserSerializer, UpdateUserSerializer, \
    DeleteUserSerializer, RoleSerializer, CustomerSerializer, VariantSerializer, Attachment_SensorSerializer


# User Management Apis
class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        customer_id = request.data.get('customer_id')

        # Check if the customer_id is valid and exists in the customer table
        if customer_id and not Customer.objects.filter(id=customer_id).exists():
            messages = "Invalid customer_id or customer does not exist."
            response_data = {
                'messages': messages
            }
            return Response(response_data, status=status.HTTP_404_NOT_FOUND)
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user_data['role'] = serializer.instance.role
        message = "User created successfully."
        response_data = {
            'message': message,
            'data': user_data
        }
        return Response(response_data, status=status.HTTP_201_CREATED)


# login user
class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_data = serializer.data
        message = "User logged in successfully"
        response_data = {
            'message': message,
            'data': user_data
        }
        return Response(response_data, status=status.HTTP_200_OK)


# logout user
class LogoutAPIView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        if self.request.data.get('all'):
            tokens = OutstandingToken.objects.filter(user=request.user)
            for token in tokens:
                token.blacklist()
            logout(request)  # Manually flush the session
            request.session.flush()  # Clear the session
            return Response({"status": "OK, goodbye, all refresh tokens blacklisted"})
        refresh_token = self.request.data.get('refresh_token')
        token = RefreshToken(refresh_token)
        token.blacklist()
        logout(request)  # Manually flush the session
        request.session.flush()  # Clear the session
        return Response({"status": "OK, goodbye"})


# get all users
class GetUsersAPIView(generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = GetUserSerializer

    # permission_classes = (permissions.IsAuthenticated,)

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

        if username and user_status:
            users_data = self.queryset.filter(username=username, is_active=user_status)
        elif username:
            users_data = self.queryset.filter(username=username)
        elif user_status:
            users_data = self.queryset.filter(is_active=user_status)
        else:
            users_data = self.get_queryset()

        serializer = self.get_serializer(users_data, many=True)
        response_data = {
            'message': 'user details listed successfully',
            'status': 'success',
            'data': serializer.data
        }
        return Response(response_data, status=200)


class UpdateUsersAPIView(generics.GenericAPIView):
    serializer_class = UpdateUserSerializer

    # permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
            update_user_data = request.data
            serializer = UpdateUserSerializer(user, data=update_user_data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            else:
                return Response(serializer.errors, status=400)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=404)


class DeleteUsersAPIView(generics.GenericAPIView):
    serializer_class = DeleteUserSerializer

    # permission_classes = (permissions.IsAuthenticated,)

    def delete(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
            user.is_active = False
            user.save()
            return Response({'message': 'User deleted successfully'})
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=404)


# Role Management Apis
class CreateRoleView(generics.GenericAPIView):
    def post(self, request):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            role_name = serializer.validated_data['role_name']

            # Check if a role with the same role_name already exists
            if Role.objects.filter(role_name=role_name).exists():
                return Response({'message': 'Role with the same name already exists.'}, status=400)

            role = serializer.save()
            return Response(RoleSerializer(role).data, status=201)
        return Response(serializer.errors, status=400)


class RoleUpdateView(generics.GenericAPIView):
    def put(self, request, role_id):
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            return Response({'message': 'Role not found.'}, status=404)

        serializer = RoleSerializer(role, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)


class RoleDeleteView(generics.GenericAPIView):
    def delete(self, request, role_id):
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            return Response({'message': 'Role not found.'}, status=404)

        role.delete()
        return Response({'message': 'Role deleted successfully.'}, status=200)


class GetRoleAPIView(generics.ListAPIView):
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


# Customer Management Apis
class CustomerCreateView(generics.CreateAPIView):
    serializer_class = CustomerSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            customer_name = serializer.validated_data['customer_name']

            # Check if a customer with the same name already exists
            if Customer.objects.filter(customer_name=customer_name).exists():
                return Response({'message': 'Customer with the same name already exists.'}, status=400)

            customer = serializer.save()
            return Response(CustomerSerializer(customer).data, status=201)

        return Response(serializer.errors, status=400)


class GetCustomerAPIView(generics.ListAPIView):
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
                return Response(response_data, status=200)
            except Customer.DoesNotExist:
                return Response({'message': 'Customer not found.'}, status=404)

        if customer_name and customer_status:
            customers = self.queryset.filter(customer_name=customer_name, customer_status=customer_status)
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
        return Response(response_data, status=200)


class UpdateCustomerAPIView(generics.UpdateAPIView):
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
    def delete(self, request, customer_id):
        try:
            customer = Customer.objects.get(id=customer_id)
        except Customer.DoesNotExist:
            return Response({'message': 'customer not found.'}, status=404)

        customer.delete()
        return Response({'message': 'customer deleted successfully.'}, status=200)


# class SensorCreateView(generics.GenericAPIView):
#     def post(self, request):
#         serializer = Attachment_SensorSerializer(data=request.data)
#         if serializer.is_valid():
#             name = serializer.validated_data['name']
#             if Attachment_or_Sensor_Master.objects.filter(name=name).exists():
#                 return Response(
#                     {"message": "A Sensor with the same name already exists."},
#                     status=status.HTTP_400_BAD_REQUEST
#                 )
#             serializer.save()
#             message = {
#                 "message": "Sensor Added Successfully",
#                 "data": serializer.data
#             }
#             return Response(message, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# update Sensor
# class UpdateSensorAPIView(generics.UpdateAPIView):
#     queryset = Sensor.objects.all()
#     serializer_class = SensorSerializer
#     lookup_field = 'sensor_id'
#
#     def put(self, request, *args, **kwargs):
#         instance = self.get_object()
#         serializer = self.get_serializer(instance, data=request.data, partial=True)
#         serializer.is_valid(raise_exception=True)
#         self.perform_update(serializer)
#         response_data = {
#             'message': 'Sensor Updated successfully',
#             'status': 'success',
#             'data': serializer.data
#         }
#         return Response(response_data)
#
#
# # Get Sensor
# class GetSensorAPIView(generics.ListAPIView):
#     queryset = Sensor.objects.all()
#     serializer_class = SensorSerializer
#
#     def get(self, request, *args, **kwargs):
#         # Get query parameters
#         sensor_id = self.request.query_params.get('sensor_id')
#         sensor_name = self.request.query_params.get('sensor_name')
#         sensor_status = self.request.query_params.get('sensor_status')
#
#         if sensor_id:
#             try:
#                 sensor = Sensor.objects.get(sensor_id=sensor_id)
#                 serializer = self.get_serializer(sensor)
#                 response_data = {
#                     'message': 'Sensor retrieved successfully',
#                     'status': 'success',
#                     'data': serializer.data
#                 }
#                 return Response(response_data, status=200)
#             except Sensor.DoesNotExist:
#                 return Response({'message': 'Sensor not found.'}, status=404)
#
#         if sensor_name and sensor_status:
#             sensors = self.queryset.filter(sensor_name=sensor_name, sensor_status=sensor_status)
#         elif sensor_name:
#             sensors = self.queryset.filter(sensor_name=sensor_name)
#         elif sensor_status:
#             sensors = self.queryset.filter(sensor_status=sensor_status)
#         else:
#             sensors = self.get_queryset()
#
#         serializer = self.get_serializer(sensors, many=True)
#         response_data = {
#             'message': 'Sensor listing successfully',
#             'status': 'success',
#             'data': serializer.data
#         }
#         return Response(response_data, status=200)
#
#
# # Delete Sensor
# class DeleteSensorAPIView(generics.DestroyAPIView):
#     def delete(self, request, sensor_id):
#         try:
#             sensor = Sensor.objects.get(sensor_id=sensor_id)
#         except Sensor.DoesNotExist:
#             return Response({'message': 'Sensor not found.'}, status=404)
#
#         sensor.delete()
#         return Response({'message': 'Sensor deleted successfully.'}, status=200)


class Attachment_Sensor_CreateView(generics.GenericAPIView):
    def post(self, request):
        serializer = Attachment_SensorSerializer(data=request.data)
        if serializer.is_valid():
            name = serializer.validated_data.get('name')
            if name is not None and Attachment_or_Sensor_Master.objects.filter(name=name).exists():
                return Response(
                    {"message": "An attachment or sensor with the same name already exists."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            serializer.save()
            message = {
                "message": "Attachment or Sensor Added Successfully",
                "data": serializer.data
            }
            return Response(message, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# upadte Attachment
# class UpdateAttachmentAPIView(generics.UpdateAPIView):
#     queryset = Attachment.objects.all()
#     serializer_class = AttachmentSerializer
#     lookup_field = 'attachment_id'
#
#     def put(self, request, *args, **kwargs):
#         instance = self.get_object()
#         serializer = self.get_serializer(instance, data=request.data, partial=True)
#         serializer.is_valid(raise_exception=True)
#         self.perform_update(serializer)
#         response_data = {
#             'message': 'Attachment Updated successfully',
#             'status': 'success',
#             'data': serializer.data
#         }
#         return Response(response_data)
#
#
# # Get Attachment
# class GetAttachmentAPIView(generics.ListAPIView):
#     queryset = Attachment.objects.all()
#     serializer_class = AttachmentSerializer
#
#     def get(self, request, *args, **kwargs):
#         # Get query parameters
#         attachment_id = self.request.query_params.get('attachment_id')
#         attachment_name = self.request.query_params.get('attachment_name')
#         attachment_status = self.request.query_params.get('attachment_status')
#
#         if attachment_id:
#             try:
#                 attachment = Attachment.objects.get(attachment_id=attachment_id)
#                 serializer = self.get_serializer(attachment)
#                 response_data = {
#                     'message': 'Attachment retrieved successfully',
#                     'status': 'success',
#                     'data': serializer.data
#                 }
#                 return Response(response_data, status=200)
#             except Attachment.DoesNotExist:
#                 return Response({'message': 'Attachment not found.'}, status=404)
#
#         if attachment_name and attachment_status:
#             attachments = self.queryset.filter(attachment_name=attachment_name, attachment_status=attachment_status)
#         elif attachment_name:
#             attachments = self.queryset.filter(attachment_name=attachment_name)
#         elif attachment_status:
#             attachments = self.queryset.filter(attachment_status=attachment_status)
#         else:
#             attachments = self.get_queryset()
#
#         serializer = self.get_serializer(attachments, many=True)
#         response_data = {
#             'message': 'Attachment listing successfully',
#             'status': 'success',
#             'data': serializer.data
#         }
#         return Response(response_data, status=200)
#
#
# # Delete Attachment
# class DeleteAttachmentAPIView(generics.DestroyAPIView):
#     def delete(self, request, attachment_id):
#         try:
#             attachment = Attachment.objects.get(attachment_id=attachment_id)
#         except Attachment.DoesNotExist:
#             return Response({'message': 'Attachment not found.'}, status=404)
#
#         attachment.delete()
#         return Response({'message': 'Attachment deleted successfully.'}, status=200)
#


# Variant Management Apis
class AddVariantCreateView(generics.CreateAPIView):
    queryset = Variant.objects.all()
    serializer_class = VariantSerializer

    def create(self, request, *args, **kwargs):
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

        return Response(variant_serializer.data, status=status.HTTP_201_CREATED)

class GetVariantAPIView(generics.ListAPIView):
    queryset = Variant.objects.all()
    serializer_class = VariantSerializer

    def get(self, request, *args, **kwargs):
        # Get query parameters
        variant_id = self.request.query_params.get('variant_id')
        variant_name = self.request.query_params.get('variant_name')
        variant_status = self.request.query_params.get('variant_status')

        if variant_id:
            try:
                variant = Variant.objects.get(variant_id=variant_id)
                serializer = self.get_serializer(variant)
                response_data = {
                    'message': 'Variant retrieved successfully',
                    'status': 'success',
                    'data': serializer.data
                }
                return Response(response_data, status=200)
            except Variant.DoesNotExist:
                return Response({'message': 'Variant not found.'}, status=404)

        if variant_name and variant_status:
            variants = self.queryset.filter(variant_name=variant_name, variant_status=variant_status)
        elif variant_name:
            variants = self.queryset.filter(variant_name=variant_name)
        elif variant_status:
            variants = self.queryset.filter(variant_status=variant_status)
        else:
            variants = self.get_queryset()

        serializer = self.get_serializer(variants, many=True)
        response_data = {
            'message': 'Variants listing successfully',
            'status': 'success',
            'data': serializer.data
        }
        return Response(response_data, status=200)


class UpdateVariantAPIView(generics.UpdateAPIView):
    queryset = Variant.objects.all()
    serializer_class = VariantSerializer

    def put(self, request, *args, **kwargs):
        variant_id = self.kwargs.get('variant_id')
        variant_data = request.data
        variant_name = variant_data.get('variant_name')
        variant_description = variant_data.get('variant_description')

        try:
            variant = Variant.objects.get(variant_id=variant_id)
        except Variant.DoesNotExist:
            return Response(
                {"error": "Variant does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )

        if variant_name:
            # Check if variant with the new name already exists
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

        return Response(self.get_serializer(instance=variant).data, status=status.HTTP_200_OK)


class DeleteVariantAPIView(generics.DestroyAPIView):
    def delete(self, request, variant_id):
        try:
            variant = Variant.objects.get(variant_id=variant_id)
        except Variant.DoesNotExist:
            return Response({'message': 'Variant not found.'}, status=404)

        variant.delete()
        return Response({'message': 'Variant deleted successfully.'}, status=200)
