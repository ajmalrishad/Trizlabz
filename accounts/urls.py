from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView, TokenObtainPairView,
)

from . import views
from .views import LogoutAPIView, UpdateUsersAPIView, DeleteUsersAPIView, CreateRoleView, RoleUpdateView, RoleDeleteView,GetRoleAPIView

urlpatterns = [
    path('register', views.RegisterView.as_view(), name="register"),
    path('login', views.LoginAPIView.as_view(), name="login"),
    path('get_users', views.GetUsersAPIView.as_view(), name="logout"),
    path('api/token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout', LogoutAPIView.as_view(), name='logout_token'),
    path('update_user/<int:pk>', UpdateUsersAPIView.as_view(), name='update_user'),
    path('delete_user/<int:pk>', DeleteUsersAPIView.as_view(), name='delete_user'),
    path('add_role', CreateRoleView.as_view(), name='add_role'),
    path('get_role/<int:role_id>', GetRoleAPIView.as_view(), name='get_role'),
    path('update_role/<int:role_id>', RoleUpdateView.as_view(), name='update_role'),
    path('delete_role/<int:role_id>', RoleDeleteView.as_view(), name='role-delete'),
]
