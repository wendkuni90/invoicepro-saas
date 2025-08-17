from django.db import models
from django.utils.translation import gettext_lazy as _
from accounts.models import User
from companies.models import Company

class Notification(models.Model):
    """Notifications pour les utilisateurs"""
    class Type(models.TextChoices):
        INVOICE_CREATED = 'invoice_created', _('Invoice Created')
        INVOICE_PAID = 'invoice_paid', _('Invoice Paid')
        INVOICE_OVERDUE = 'invoice_overdue', _('Invoice Overdue')
        PAYMENT_RECEIVED = 'payment_received', _('Payment Received')
        SUBSCRIPTION_EXPIRING = 'subscription_expiring', _('Subscription Expiring')
        LIMIT_REACHED = 'limit_reached', _('Limit Reached')

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='notifications')
    type = models.CharField(max_length=50, choices=Type.choices)
    title = models.CharField(max_length=255)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Notification')
        verbose_name_plural = _('Notifications')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} for {self.user.email} ({self.created_at.strftime('%Y-%m-%d')})"

class ActivityLog(models.Model):
    """Journaux d'activités pour l'audit"""
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='activity_logs')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='activity_logs')
    action = models.CharField(max_length=50)
    entity_type = models.CharField(max_length=50)
    entity_id = models.IntegerField()
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Activity Log')
        verbose_name_plural = _('Activity Logs')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.action} on {self.entity_type} by {self.user.email if self.user else 'Unknown'}"
