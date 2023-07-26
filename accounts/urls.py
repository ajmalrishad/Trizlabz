from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView, TokenObtainPairView,
)

from . import views
from .views import LogoutAPIView, UpdateUsersAPIView, DeleteUsersAPIView, CreateRoleView, RoleUpdateView, \
    RoleDeleteView, GetRoleAPIView, CustomerCreateView, GetCustomerAPIView, UpdateCustomerAPIView, \
    DeleteCustomerAPIView, AddVariantCreateView, GetVariantAPIView, UpdateVariantAPIView, DeleteVariantAPIView, \
    Attachment_Sensor, GetAttachment_SensorAPIView, UpdateAttachmentAPIView, DeleteAttachment_SensorAPIView, \
    AddMapCreateView, GetMapListAPIView, UpdateMapAPIView, DeleteMapAPIView, AddDeploymentCreateView, \
    UpdateDeploymentView, GetDeploymentAPIView, DeleteDeploymentAPIView, AddVehicleAPIView, UpdateVehicleAPIView, \
    GetVehicleAPIView, DeleteVehicleAPIView, AddFleetAPIView, UpdateFleetAPIView, GetFleetAPIView, DeleteFleetAPIView, \
    AddGroupAPIView, UpdateGroupAPIView, GetGroupAPIView, DeleteGroupAPIView, AddActionAPIView, UpdateActionAPIView, \
    GetActionAPIView, DeleteActionAPIView

urlpatterns = [
    # User Management And Token
    path('register', views.RegisterView.as_view(), name="register"),
    path('login', views.LoginAPIView.as_view(), name="login"),
    path('get_users', views.GetUsersAPIView.as_view(), name="logout"),
    path('api/token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout', LogoutAPIView.as_view(), name='logout_token'),
    path('update_user/<int:pk>', UpdateUsersAPIView.as_view(), name='update_user'),
    path('delete_user/<int:pk>', DeleteUsersAPIView.as_view(), name='delete_user'),
    # Role Management
    path('add_role', CreateRoleView.as_view(), name='add_role'),
    path('get_role', GetRoleAPIView.as_view(), name='role-list'),
    path('update_role/<int:role_id>', RoleUpdateView.as_view(), name='update_role'),
    path('delete_role/<int:role_id>', RoleDeleteView.as_view(), name='role-delete'),
    # Customer Management
    path('addcustomer', CustomerCreateView.as_view(), name='customer-create'),
    path('getcustomer', GetCustomerAPIView.as_view(), name='customer-get'),
    path('updatecustomer/<int:id>', UpdateCustomerAPIView.as_view(), name='customer-update'),
    path('deletecustomer/<int:id>', DeleteCustomerAPIView.as_view(), name='customer-delete'),
    # Attachmet or Sensor Management
    path('add_attachment_or_sensor', Attachment_Sensor.as_view(), name='add-attachment'),
    path('update_attachment_or_sensor/<int:id>', UpdateAttachmentAPIView.as_view(),
         name='update-attachment'),
    path('get_attachment_or_sensor', GetAttachment_SensorAPIView.as_view(), name='get-attachment'),
    path('delete_attachment_sensor', DeleteAttachment_SensorAPIView.as_view(), name='delete-attachment'),
    # Variant Management
    path('addvariant', AddVariantCreateView.as_view(), name='addvariant'),
    path('getvariant/<int:pk>', GetVariantAPIView.as_view(), name='variant-get'),
    path('updatevariant/<int:variant_id>', UpdateVariantAPIView.as_view(), name='variant-update'),
    path('deletevariant/<int:variant_id>', DeleteVariantAPIView.as_view(), name='variant-delete'),
    # Map Management
    path('addmap', AddMapCreateView.as_view(), name='addmap'),
    path('getmap', GetMapListAPIView.as_view(), name='get-map'),
    path('updatemap/<int:id>', UpdateMapAPIView.as_view(), name='update'),
    path('deletemap/<int:id>', DeleteMapAPIView.as_view(), name='delete'),
    # Deployment Management
    path('adddeployment', AddDeploymentCreateView.as_view(), name='adddeployment'),
    path('updatedeployment/<int:id>', UpdateDeploymentView.as_view(), name='update-deployment'),
    path('getdeployment', GetDeploymentAPIView.as_view(), name='get-deployment'),
    path('deletedeployment/<int:id>', DeleteDeploymentAPIView.as_view(), name='delete'),
    # Vehicle Management
    path('addvehicle', AddVehicleAPIView.as_view(), name='addvehicle'),
    path('updatevehicle/<int:pk>', UpdateVehicleAPIView.as_view(), name='update-vehicle'),
    path('getvehicle', GetVehicleAPIView.as_view(), name='get-vehicle'),
    path('deletevehicle/<int:id>', DeleteVehicleAPIView.as_view(), name='delete_vehicle'),
    # Fleet Management
    path('addfleet', AddFleetAPIView.as_view(), name='addfleet'),
    path('updatefleet/<int:pk>', UpdateFleetAPIView.as_view(), name='update-fleet'),
    path('getfleet', GetFleetAPIView.as_view(), name='get-fleet'),
    path('deletefleet/<int:id>', DeleteFleetAPIView.as_view(), name='delete-fleet'),
    # User Group Management
    path('addgroup', AddGroupAPIView.as_view(), name='addgroup'),
    path('updategroup/<int:id>', UpdateGroupAPIView.as_view(), name='update'),
    path('getgroup', GetGroupAPIView.as_view(), name='getgroup'),
    path('deletegroup/<int:id>', DeleteGroupAPIView.as_view(), name='delete-fleet'),
    # Mission Management
    path('api/administration/action-management/add-action', AddActionAPIView.as_view(), name='add-action'),
    path('api/administration/action-management/update-action/<int:id>', UpdateActionAPIView.as_view(), name='update-action'),
    path('api/administration/action-management/get-action', GetActionAPIView.as_view(), name='get-action'),
    path('api/administration/action-management/delete-action/<int:id>', DeleteActionAPIView.as_view(), name='delete-action'),
]
