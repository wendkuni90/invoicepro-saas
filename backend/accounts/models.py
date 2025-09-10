from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

# Create your models here.
class User(AbstractUser):

    """Extension du modèle User de Django pour inclure des champs personnalisés"""

    class Role(models.TextChoices):
        SUPER_ADMIN = 'super_admin', _('Super Admin')
        COMPANY_ADMIN = 'company_admin', _('Company Admin')
        EMPLOYEE = 'employee', _('Employee')

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

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')

    def __str__(self):
        return f"{self.email} ({self.get_role_display()})"
