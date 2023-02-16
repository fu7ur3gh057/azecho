from django.urls import path
from rest_framework_simplejwt.views import (TokenRefreshView)

from apps.users.api.views import RegisterAPIView, VerifyEmailAPIView, LoginAPIView, LogoutAPIView, \
    UpdatePasswordAPIView, RequestPasswordResetEmailAPIView, PasswordTokenCheckAPIView, SetNewPasswordAPIView

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('email-verify/', VerifyEmailAPIView.as_view(), name='email-verify'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('password/update/', UpdatePasswordAPIView.as_view(), name='update-password'),
    # 3 step
    path('password/request/', RequestPasswordResetEmailAPIView.as_view(), name='request-password'),
    path('password/<uidb64>/<token>/', PasswordTokenCheckAPIView.as_view(), name='token-check-password'),
    path('password/set/', SetNewPasswordAPIView.as_view(), name='set-password'),
    path('delete/', TokenRefreshView.as_view(), name='token_refresh'),
]
