from django.forms import ValidationError
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
from rest_framework.throttling import ScopedRateThrottle

from .utils_audit import create_audit_log
from audit.models import AuditLog
from .throttles import LoginRateThrottle
from .utils import verify_captcha
from django.core.cache import cache
from django.utils import timezone

from .serializers import UserSessionSerializer
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken

from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User, UserSession
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
        captcha_token = self.request.data.get("captcha_token")
        if not captcha_token or not verify_captcha(captcha_token, self.request.META.get("REMOTE_ADDR")):
            raise ValidationError({"captcha": "Échec de la vérification captcha"})

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
    throttle_classes = [LoginRateThrottle]  # limite à 5 tentatives / minute

    def post(self, request):
        ip = request.META.get("REMOTE_ADDR", "unknown")
        fail_key = f"login_failures_{ip}"

        # Captcha requis après 3 échecs
        if cache.get(fail_key, 0) >= 3:
            captcha_token = request.data.get("captcha_token")
            if not captcha_token or not verify_captcha(captcha_token, ip):
                return Response(
                    {"detail": "Captcha requis ou invalide"},
                    status=400
                )

        # Validation des identifiants
        serializer = LoginSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError:
            # incrémente compteur échecs (expire en 5 min)
            cache.set(fail_key, cache.get(fail_key, 0) + 1, timeout=300)
            # Audit login failed
            create_audit_log(
                user=None,
                action_type=AuditLog.ActionType.LOGIN,
                request=request,
                response_status=400,
                response_body=serializer.errors,
                entity_type="AUTH",
                changes={"result": "FAILED"}
            )
            raise

        # Login réussi → reset compteur
        cache.delete(fail_key)

        user: User = serializer.validated_data
        tokens = get_tokens_for_user(user)
        refresh_obj = RefreshToken(tokens["refresh"])
        refresh_jti = str(refresh_obj["jti"])
        ip = request.META.get("REMOTE_ADDR", "unknown")
        ua = request.META.get("HTTP_USER_AGENT", "unknown")

        user_session = UserSession.objects.create(
            user=user,
            refresh_jti=refresh_jti,
            ip_address=ip,
            user_agent=ua,
            last_activity=timezone.now(),
        )

        login(request, user)

        # Réponse + cookies sécurisés
        response = Response({
            "user": UserSerializer(user).data,
            "message": "Login successful"
        })

        secure_cookie = not settings.DEBUG  # True en prod

        response.set_cookie(
            key="access_token",
            value=tokens["access"],
            httponly=True,
            secure=secure_cookie,
            samesite="Lax",   # Strict si même domaine, None si sous-domaines HTTPS
            max_age=60 * 60   # 1h
        )

        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh"],
            httponly=True,
            secure=secure_cookie,
            samesite="Lax",
            max_age=7 * 24 * 60 * 60  # 7 jours
        )

        # cookie de session (identifie la session courante côté client)
        response.set_cookie(
            key="session_id",
            value=str(user_session.session_id),
            httponly=True,
            secure=secure_cookie,
            samesite="Lax",
            max_age=7 * 24 * 60 * 60
        )

        # Audit login success
        create_audit_log(
            user=user,
            action_type=AuditLog.ActionType.LOGIN,
            request=request,
            response_status=200,
            response_body={"message": "Login successful"},
            entity_type="AUTH",
            changes={"result": "SUCCESS"}
        )

        return response

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

        response = Response({"detail": "Déconnexion réussie"}, status=200)
        response.delete_cookie("refresh_token")
        response.delete_cookie("access_token")

        # Audit logout
        create_audit_log(
            user=request.user,
            action_type=AuditLog.ActionType.LOGOUT,
            request=request,
            response_status=200,
            response_body={"detail": "Déconnexion réussie"},
            entity_type="AUTH",
            changes={"result": "SUCCESS"}
        )

        return response


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
        link = f"{settings.BACKEND_URL}/api/accounts/password-reset-confirm/{uid}/{token}"
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

        # Audit
        create_audit_log(
            user=user,
            action_type=AuditLog.ActionType.ACTIVITY_LOG,
            request=request,
            response_status=200,
            response_body={"detail": "2FA activé"},
            entity_type="AUTH",
            changes={"result": "2FA_ENABLED"}
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
            create_audit_log(
                user=user,
                action_type=AuditLog.ActionType.ACTIVITY_LOG,
                request=request,
                response_status=400,
                response_body={"detail": "Code 2FA invalide"},
                entity_type="AUTH",
                changes={"result": "2FA_FAILED"}
            )
            return Response({"detail": "Code 2FA invalide"}, status=400)

        create_audit_log(
            user=user,
            action_type=AuditLog.ActionType.ACTIVITY_LOG,
            request=request,
            response_status=200,
            response_body={"detail": "2FA validé"},
            entity_type="AUTH",
            changes={"result": "2FA_VERIFIED"}
        )

        return Response({"detail": "2FA validé"})

class CookieTokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            return Response({"detail": "Refresh token manquant"}, status=400)
        try:
            refresh = RefreshToken(refresh_token)
            return Response({"access": str(refresh.access_token)})
        except Exception:
            return Response({"detail": "Token invalide ou expiré"}, status=400)

class SessionListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSessionSerializer

    def get_queryset(self):
        return UserSession.objects.filter(user=self.request.user).order_by("-last_activity")

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["request"] = self.request
        return ctx


class SessionRevokeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, session_id):
        try:
            session = UserSession.objects.get(user=request.user, session_id=session_id, revoked=False)
        except UserSession.DoesNotExist:
            return Response({"detail": "Session introuvable ou déjà révoquée"}, status=404)

        # Blacklist du refresh associé via le jti
        try:
            ot = OutstandingToken.objects.get(jti=session.refresh_jti, user=request.user)
            BlacklistedToken.objects.get_or_create(outstanding_token=ot)
        except OutstandingToken.DoesNotExist:
            pass  # si pas trouvé, on révoque quand même la session applicative

        session.revoked = True
        session.revoked_at = timezone.now()
        session.revoked_reason = "Revoked by user"
        session.save(update_fields=["revoked", "revoked_at", "revoked_reason"])

        # Si on révoque la session courante → on supprime aussi les cookies côté client
        current = request.COOKIES.get("session_id")
        response = Response({"detail": "Session révoquée"}, status=200)
        if current and str(session.session_id) == current:
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            response.delete_cookie("session_id")
        return response


class SessionRevokeOthersView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        current = request.COOKIES.get("session_id")
        qs = UserSession.objects.filter(user=request.user, revoked=False)
        if current:
            qs = qs.exclude(session_id=current)

        count = 0
        for s in qs:
            try:
                ot = OutstandingToken.objects.get(jti=s.refresh_jti, user=request.user)
                BlacklistedToken.objects.get_or_create(outstanding_token=ot)
            except OutstandingToken.DoesNotExist:
                pass
            s.revoked = True
            s.revoked_at = timezone.now()
            s.revoked_reason = "Revoked others by user"
            s.save(update_fields=["revoked", "revoked_at", "revoked_reason"])
            count += 1

        return Response({"detail": f"{count} session(s) révoquée(s)"}, status=200)
