from django.db import models
from django.utils.translation import gettext_lazy as _
from companies.models import Company

class Subscription(models.Model):
    """Abonnements des entreprises au SaaS"""
    class PlanType(models.TextChoices):
        FREE = 'free', _('Free')
        PREMIUM = 'premium', _('Premium')
        ENTERPRISE = 'enterprise', _('Enterprise')

    class Status(models.TextChoices):
        ACTIVE = 'active', _('Active')
        CANCELED = 'canceled', _('Canceled')
        PAST_DUE = 'past_due', _('Past Due')
        TRIALING = 'trialing', _('Trialing')

    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='subscriptions')
    plan_type = models.CharField(max_length=50, choices=PlanType.choices, default=PlanType.FREE)
    stripe_subscription_id = models.CharField(max_length=255, blank=True, null=True)
    stripe_customer_id = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=50, choices=Status.choices, default=Status.ACTIVE)
    current_period_start = models.DateTimeField(blank=True, null=True)
    current_period_end = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Subscription')
        verbose_name_plural = _('Subscriptions')

    def __str__(self):
        return f"{self.company.name} - {self.get_plan_type_display()} ({self.get_status_display()})"

