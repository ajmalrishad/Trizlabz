from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView, TokenObtainPairView,
)

from . import views
from .views import LogoutAPIView, UpdateUsersAPIView,DeleteUsersAPIView

urlpatterns = [
    path('register', views.RegisterView.as_view(), name="register"),
    path('login', views.LoginAPIView.as_view(), name="login"),
    path('get_users', views.GetUsersAPIView.as_view(), name="logout"),
    path('api/token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout', LogoutAPIView.as_view(), name='logout_token'),
    path('update_user/<int:pk>', UpdateUsersAPIView.as_view(), name='update_user'),
    path('delete_user/<int:pk>', DeleteUsersAPIView.as_view(), name='delete_user'),

]
