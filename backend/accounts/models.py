from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
import uuid
from django.utils import timezone
from django.conf import settings

class CustomUserManager(BaseUserManager):
    """Manager personnalisé pour utiliser email comme identifiant"""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("L'email est obligatoire")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("role", User.Role.SUPER_ADMIN)

        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):

    """Extension du modèle User de Django pour inclure des champs personnalisés"""

    class Role(models.TextChoices):
        SUPER_ADMIN = 'super_admin', _('Super Admin')
        COMPANY_ADMIN = 'company_admin', _('Company Admin')
        EMPLOYEE = 'employee', _('Employee')

    username = None

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.EMPLOYEE,
    )

    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    email_verified = models.BooleanField(default=False)

    last_login = models.DateTimeField(blank=True, null=True)

    # 2FA
    is_2fa_enabled = models.BooleanField(default=False)
    twofa_secret = models.CharField(max_length=64, blank=True, null=True) # Clé TOTP

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')

    def __str__(self):
        return f"{self.email} ({self.get_role_display()})"


# ========== SESSIONS ==========
class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sessions")
    session_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)  # pour le cookie "session_id"
    refresh_jti = models.CharField(max_length=64, db_index=True)  # JTI du refresh JWT
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)
    device_name = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(default=timezone.now)
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        ordering = ["-last_activity"]

    def __str__(self):
        return f"{self.user.email} - {self.session_id}"

