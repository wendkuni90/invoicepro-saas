from django.db import models
from django.utils.translation import gettext_lazy as _
from accounts.models import User

# Create your models here.
class Company(models.Model):
    """Modèle pour les entreprises utilisant le SaaS"""
    name = models.CharField(max_length=255)
    legal_name = models.CharField(max_length=255, blank=True, null=True)
    tax_number = models.CharField(max_length=100, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    website = models.URLField(blank=True, null=True)
    logo_url = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Company')
        verbose_name_plural = _('Companies')

    def __str__(self):
        return self.name

class CompanyUser(models.Model):
    """Association entre utilisateurs et entreprises avec permissions"""
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='company_users')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='company_memberships')

    class Role(models.TextChoices):
        ADMIN = 'admin', _('Admin')
        EMPLOYEE = 'employee', _('Employee')

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.EMPLOYEE,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    permissions = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = _('Company User')
        verbose_name_plural = _('Company Users')
        unique_together = ('company', 'user')

    def __str__(self):
        return f"{self.user.email} at {self.company.name} ({self.get_role_display()})"
