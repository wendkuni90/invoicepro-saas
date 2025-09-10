import pyotp, qrcode
from io import BytesIO
from django.core.mail import send_mail
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User
from .serializers import (
    RegisterSerializer, LoginSerializer, UserSerializer,
    VerifyEmailSerializer, PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer, PasswordChangeSerializer,
    TwoFASerializer
)

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {"refresh": str(refresh), "access": str(refresh.access_token)}

# Inscription
class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        # link = f"{settings.FRONTEND_URL}/verify-email/{uid}/{token}" # (Quand le frontend sera fait)
        link = f"{settings.BACKEND_URL}/api/accounts/verify-email/{uid}/{token}"
        # send_mail(
        #     "Vérifiez votre email - InvoicePro",
        #     f"Cliquez sur ce lien pour activer votre compte (valide 10 minutes) : {link}",
        #     settings.DEFAULT_FROM_EMAIL,
        #     [user.email],
        #     fail_silently=False
        # )
        subject = "Vérifiez votre email - InvoicePro"
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = [user.email]

        # Contexte pour le template
        context = {
            "user": user,
            "link": link,
            "validity_minutes": 10,
        }

        # Générer contenu texte + HTML
        text_content = render_to_string("emails/verify_email.txt", context)
        html_content = render_to_string("emails/verify_email.html", context)

        msg = EmailMultiAlternatives(subject, text_content, from_email, to_email)
        msg.attach_alternative(html_content, "text/html")
        msg.send()

# Connexion
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        tokens = get_tokens_for_user(user)
        login(request, user)
        return Response({"user": UserSerializer(user).data, "tokens": tokens})

# Déconnexion
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception:
            pass
        logout(request)
        return Response({"detail": "Déconnexion réussie"}, status=status.HTTP_200_OK)

# Vérification email
class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"detail": "Lien invalide"}, status=400)

        if default_token_generator.check_token(user, token):
            user.email_verified = True
            user.save()
            return Response({"detail": "Email vérifié"})
        return Response({"detail": "Lien invalide ou expiré"}, status=400)

# Demande reset password
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"detail": "Utilisateur non trouvé"}, status=404)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        # link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}" # (Quand il y'aura un frontend fonctionnel)
        link = f"{settings.BACKEND_URL}/api/accounts/reset-password/{uid}/{token}"
        # send_mail(
        #     "Réinitialisation de mot de passe - InvoicePro",
        #     f"Cliquez sur ce lien pour réinitialiser votre mot de passe (valide 10 minutes) : {link}",
        #     settings.DEFAULT_FROM_EMAIL,
        #     [user.email],
        # )
        subject = "Réinitialisation de mot de passe - InvoicePro"
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = [user.email]

        context = {
            "user": user,
            "link": link,
            "validity_minutes": 10,
        }

        # Générer contenu texte + HTML
        text_content = render_to_string("emails/password_reset.txt", context)
        html_content = render_to_string("emails/password_reset.html", context)

        msg = EmailMultiAlternatives(subject, text_content, from_email, to_email)
        msg.attach_alternative(html_content, "text/html")
        msg.send()

        return Response({"detail": "Email de réinitialisation envoyé"})

# Confirmation reset password
class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({"detail": "Lien invalide"}, status=400)

        if not default_token_generator.check_token(user, token):
            return Response({"detail": "Lien invalide ou expiré"}, status=400)

        user.set_password(serializer.validated_data["new_password"])
        user.save()
        return Response({"detail": "Mot de passe réinitialisé"})

# Changement mot de passe
class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        if not user.check_password(serializer.validated_data["old_password"]):
            return Response({"detail": "Ancien mot de passe incorrect"}, status=400)
        user.set_password(serializer.validated_data["new_password"])
        user.save()
        return Response({"detail": "Mot de passe changé avec succès"})

# 2FA activation
class TwoFAEnableView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if not user.twofa_secret:
            secret = pyotp.random_base32()
            user.twofa_secret = secret
            user.is_2fa_enabled = True
            user.save()
        else:
            secret = user.twofa_secret

        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email, issuer_name="InvoicePro"
        )
        return Response({"secret": secret, "otp_uri": otp_uri})

# 2FA vérification
class TwoFAVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TwoFASerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]

        user = request.user
        if not user.twofa_secret:
            return Response({"detail": "2FA non activé"}, status=400)

        totp = pyotp.TOTP(user.twofa_secret)
        if not totp.verify(token):
            return Response({"detail": "Code 2FA invalide"}, status=400)

        return Response({"detail": "2FA validé"})
