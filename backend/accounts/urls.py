from django.urls import path
from .views import (
    RegisterView, LoginView, LogoutView,
    VerifyEmailView, PasswordResetRequestView, PasswordResetConfirmView,
    PasswordChangeView, TwoFAEnableView, TwoFAVerifyView
)

urlpatterns = [
    path("register/", RegisterView.as_view()),
    path("login/", LoginView.as_view()),
    path("logout/", LogoutView.as_view()),
    path("verify-email/<uidb64>/<token>/", VerifyEmailView.as_view()),
    path("password-reset/", PasswordResetRequestView.as_view()),
    path("password-reset-confirm/<uidb64>/<token>/", PasswordResetConfirmView.as_view()),
    path("password-change/", PasswordChangeView.as_view()),
    path("2fa/enable/", TwoFAEnableView.as_view()),
    path("2fa/verify/", TwoFAVerifyView.as_view()),
]

