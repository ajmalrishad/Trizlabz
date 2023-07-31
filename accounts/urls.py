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
    GetActionAPIView, DeleteActionAPIView, AddMissionAPIView, UpdateMissionAPIView, GetMissionAPIView, \
    DeleteMissionAPIView, DashBoardAPIView

urlpatterns = [
    # User Management
    path('api/administration/user-management/add-user', views.RegisterView.as_view(), name="register"),
    path('api/login', views.LoginAPIView.as_view(), name="login"),
    path('api/administration/user-management/get-user', views.GetUsersAPIView.as_view(), name="logout"),
    path('api/logout', LogoutAPIView.as_view(), name='logout_token'),
    path('api/administration/user-management/update-user/<int:id>', UpdateUsersAPIView.as_view(), name='update_user'),
    path('api/administration/user-management/delete-user/<int:id>', DeleteUsersAPIView.as_view(), name='delete_user'),
    # Token Management
    path('api/token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    # Role Management
    path('api/administration/role-management/add-role', CreateRoleView.as_view(), name='add_role'),
    path('api/administration/role-management/get-role', GetRoleAPIView.as_view(), name='role-list'),
    path('api/administration/role-management/update-role/<int:role_id>', RoleUpdateView.as_view(), name='update_role'),
    path('api/administration/role-management/delete-role/<int:role_id>', RoleDeleteView.as_view(), name='role-delete'),
    # Customer Management
    path('api/administration/customer-management/add-customer', CustomerCreateView.as_view(), name='customer-create'),
    path('api/administration/customer-management/get-customer', GetCustomerAPIView.as_view(), name='customer-get'),
    path('api/administration/customer-management/update-customer/<int:id>', UpdateCustomerAPIView.as_view(),
         name='customer-update'),
    path('api/administration/customer-management/delete-customer/<int:id>', DeleteCustomerAPIView.as_view(),
         name='customer-delete'),
    # Attachmet or Sensor Management
    path('api/administration/attachment-sensor-management/add-attachment-sensor', Attachment_Sensor.as_view(),
         name='add-attachment'),
    path('api/administration/attachment-sensor-management/update-attachment-sensor/<int:id>',
         UpdateAttachmentAPIView.as_view(), name='update-attachment'),
    path('api/administration/attachment-sensor-management/get-attachment-sensor', GetAttachment_SensorAPIView.as_view(),
         name='get-attachment'),
    path('api/administration/attachment-sensor-management/delete-attachment-sensor',
         DeleteAttachment_SensorAPIView.as_view(), name='delete-attachment'),
    # Variant Management
    path('api/administration/variant-management/add-variant', AddVariantCreateView.as_view(), name='addvariant'),
    path('api/administration/variant-management/get-variant', GetVariantAPIView.as_view(), name='variant-get'),
    path('api/administration/variant-management/update-variant/<int:variant_id>', UpdateVariantAPIView.as_view(),
         name='variant-update'),
    path('api/administration/variant-management/delete-variant/<int:variant_id>', DeleteVariantAPIView.as_view(),
         name='variant-delete'),
    # Map Management
    path('api/setup/map-management/add-map', AddMapCreateView.as_view(), name='addmap'),
    path('api/setup/map-management/get-map', GetMapListAPIView.as_view(), name='get-map'),
    path('api/setup/map-management/update-map/<int:id>', UpdateMapAPIView.as_view(), name='update'),
    path('api/setup/map-management/delete-map/<int:id>', DeleteMapAPIView.as_view(), name='delete'),
    # Deployment Management
    path('api/setup/deployment-management/add-deployment', AddDeploymentCreateView.as_view(), name='adddeployment'),
    path('api/setup/deployment-management/update-deployment/<int:id>', UpdateDeploymentView.as_view(),
         name='update-deployment'),
    path('api/setup/deployment-management/get-deployment', GetDeploymentAPIView.as_view(), name='get-deployment'),
    path('api/setup/deployment-management/delete-deployment/<int:id>', DeleteDeploymentAPIView.as_view(),
         name='delete'),
    # Vehicle Management
    path('api/administration/vehicle-management/add-vehicle', AddVehicleAPIView.as_view(), name='addvehicle'),
    path('api/administration/vehicle-management/update-vehicle/<int:pk>', UpdateVehicleAPIView.as_view(),
         name='update-vehicle'),
    path('api/administration/vehicle-management/get-vehicle', GetVehicleAPIView.as_view(), name='get-vehicle'),
    path('api/administration/vehicle-management/delete-vehicle/<int:id>', DeleteVehicleAPIView.as_view(),
         name='delete_vehicle'),
    # Fleet Management
    path('api/setup/fleet-management/add-fleet', AddFleetAPIView.as_view(), name='addfleet'),
    path('api/setup/fleet-management/update-fleet/<int:pk>', UpdateFleetAPIView.as_view(), name='update-fleet'),
    path('api/setup/fleet-management/get-fleet', GetFleetAPIView.as_view(), name='get-fleet'),
    path('api/setup/fleet-management/delete-fleet/<int:id>', DeleteFleetAPIView.as_view(), name='delete-fleet'),
    # User Group Management
    path('api/setup/usergroup-management/add-usergroup', AddGroupAPIView.as_view(), name='addgroup'),
    path('api/setup/usergroup-management/update-usergroup/<int:id>', UpdateGroupAPIView.as_view(), name='update'),
    path('api/setup/usergroup-management/get-usergroup', GetGroupAPIView.as_view(), name='getgroup'),
    path('api/setup/usergroup-management/delete-usergroup/<int:id>', DeleteGroupAPIView.as_view(), name='delete-fleet'),
    # Action Management
    path('api/administration/action-management/add-action', AddActionAPIView.as_view(), name='add-action'),
    path('api/administration/action-management/update-action/<int:id>', UpdateActionAPIView.as_view(),
         name='update-action'),
    path('api/administration/action-management/get-action', GetActionAPIView.as_view(), name='get-action'),
    path('api/administration/action-management/delete-action/<int:id>', DeleteActionAPIView.as_view(),
         name='delete-action'),
    # Mission Management
    path('api/setup/mission-management/add-mission', AddMissionAPIView.as_view(), name='add-mission'),
    path('api/setup/mission-management/update-mission/<int:id>', UpdateMissionAPIView.as_view(), name='update-mission'),
    path('api/setup/mission-management/get-mission', GetMissionAPIView.as_view(), name='get-mission'),
    path('api/setup/mission-management/delete-mission/<int:id>', DeleteMissionAPIView.as_view(), name='delete-mission'),
    # Dash Board
    path('api/dashboard', DashBoardAPIView.as_view(), name='dashboard'),
]
