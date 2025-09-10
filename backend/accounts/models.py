from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _

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
