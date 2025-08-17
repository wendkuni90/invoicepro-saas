from django.db import models
from django.utils.translation import gettext_lazy as _
from accounts.models import User

# Create your models here.
class AuditLog(models.Model):
    """Audit plus formel (juridique/comptable) des actions effectuées dans le système"""
    class ActionType(models.TextChoices):
        CREATE = 'create', _('Create')
        UPDATE = 'update', _('Update')
        DELETE = 'delete', _('Delete')
        LOGIN = 'login', _('Login')
        LOGOUT = 'logout', _('Logout')
        VIEW = 'view', _('View')
        EXPORT = 'export', _('Export')
        IMPORT = 'import', _('Import')
        NOTIFICATION = 'notification', _('Notification')
        PAYMENT = 'payment', _('Payment')
        SUBSCRIPTION = 'subscription', _('Subscription')
        INVOICE = 'invoice', _('Invoice')
        CLIENT = 'client', _('Client')
        COMPANY = 'company', _('Company')
        USER = 'user', _('User')
        SETTINGS = 'settings', _('Settings')
        ACTIVITY_LOG = 'activity_log', _('Activity Log')


    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='audit_logs')
    action_type = models.CharField(max_length=20, choices=ActionType.choices)
    entity_type = models.CharField(max_length=50)  # e.g., 'Invoice', 'Client', etc.
    entity_id = models.PositiveIntegerField()  # ID of the entity being audited
    data_before = models.JSONField(blank=True, null=True)  # Data before the action
    data_after = models.JSONField(blank=True, null=True)  # Data after the action
    ip_address = models.GenericIPAddressField(blank=True, null=True)  # IP address of the user
    user_agent = models.CharField(max_length=255, blank=True, null=True)
    session_id = models.CharField(max_length=255, blank=True, null=True)  # Session ID if applicable
    request_method = models.CharField(max_length=10, blank=True, null=True)  # e.g., 'GET', 'POST'
    request_url = models.URLField(blank=True, null=True)  # URL of the request
    request_headers = models.JSONField(blank=True, null=True)  # Headers of the request
    request_body = models.TextField(blank=True, null=True)  # Body of the request
    response_status = models.IntegerField(blank=True, null=True)  # HTTP status code of the response
    response_body = models.TextField(blank=True, null=True)  # Body of the response
    response_headers = models.JSONField(blank=True, null=True)  # Headers of the response
    related_model = models.CharField(max_length=100, blank=True, null=True)  # Related model if applicable
    related_object_id = models.PositiveIntegerField(blank=True, null=True)  # ID of
    changes = models.JSONField(blank=True, null=True)  # Store changes made
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Audit Log')
        verbose_name_plural = _('Audit Logs')
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user.email} - {self.get_action_type_display()} {self.model_name} #{self.object_id} at {self.timestamp}"
