from django.db import models
from companies.models import Company
from django.utils.translation import gettext_lazy as _

# Create your models here.
class GlobalSettings(models.Model):
    """Modèle pour les paramètres globaux de l'application"""
    site_name = models.CharField(max_length=255, default="InvoicePro SaaS")
    site_description = models.TextField(blank=True, null=True)
    site_logo = models.ImageField(upload_to="global_logos/", blank=True, null=True)
    support_email = models.EmailField(blank=True, null=True, default="elielnikiema16@gmail.com")
    default_currency = models.CharField(max_length=10, default="XOF")
    default_language = models.CharField(max_length=10, default="fr")
    contact_phone = models.CharField(max_length=20, blank=True, null=True)
    allow_registration = models.BooleanField(default=True)
    enable_notifications = models.BooleanField(default=True)
    payment_gateway = models.CharField(max_length=50, choices=[
        ('stripe', 'Stripe'),
        ('paypal', 'PayPal'),
        ('mollie', 'Mollie'),
        ('razorpay', 'Razorpay'),
        ('paystack', 'Paystack'),
        ('flutterwave', 'Flutterwave'),
        ('square', 'Square'),
        ('braintree', 'Braintree'),
        ('manual', 'Manual')
    ], default='stripe')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Global Setting'
        verbose_name_plural = 'Global Settings'

    def __str__(self):
        return self.site_name


class CompanySettings(models.Model):
    """Paramètres spécifiques à chaque entreprise"""
    company = models.OneToOneField(Company, on_delete=models.CASCADE, related_name='settings')
    logo = models.ImageField(upload_to="company_logos/", blank=True, null=True)
    invoice_prefix = models.CharField(max_length=10, blank=True, null=True, default='INV')
    currency = models.CharField(max_length=10, default="XOF")
    language = models.CharField(max_length=10, default="fr")
    timezone = models.CharField(max_length=50, default="Africa/Burkina")
    invoice_template = models.TextField(blank=True, null=True, default="default_template.html")
    invoice_next_number = models.IntegerField(default=1)
    default_payment_terms = models.IntegerField(default=30)
    default_tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    email_settings = models.JSONField(default=dict, blank=True)
    notification_settings = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Company Settings')
        verbose_name_plural = _('Company Settings')

    def __str__(self):
        return f"Settings for {self.company.name}"
