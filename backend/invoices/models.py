from django.db import models
from django.utils.translation import gettext_lazy as _
from companies.models import Company
from clients.models import Client
from products.models import Product
from accounts.models import User

class Invoice(models.Model):
    """Factures émises par les entreprises"""
    class Status(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        SENT = 'sent', _('Sent')
        PAID = 'paid', _('Paid')
        OVERDUE = 'overdue', _('Overdue')
        CANCELED = 'canceled', _('Canceled')

    class PaymentStatus(models.TextChoices):
        UNPAID = 'unpaid', _('Unpaid')
        PARTIAL = 'partial', _('Partially Paid')
        PAID = 'paid', _('Paid')
        OVERDUE = 'overdue', _('Overdue')

    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='invoices')
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='invoices')
    created_by_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_invoices')
    invoice_number = models.CharField(max_length=50, unique=True)
    issue_date = models.DateField()
    due_date = models.DateField()
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT,
    )
    subtotal = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    tax_total = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    notes = models.TextField(blank=True, null=True)
    terms = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    pdf_url = models.TextField(blank=True, null=True)
    payment_status = models.CharField(max_length=20, choices=PaymentStatus.choices, default=PaymentStatus.UNPAID)

    class Meta:
        verbose_name = _('Invoice')
        verbose_name_plural = _('Invoices')
        unique_together = ('company', 'invoice_number')

    def __str__(self):
        return f"Invoice {self.invoice_number} - {self.client.name} - ({self.total}) ({self.get_status_display()})"

class InvoiceItem(models.Model):
    """Lignes de facturation pour chaque facture"""
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True, blank=True, related_name='invoice_items')
    description = models.TextField(blank=True, null=True)
    quantity = models.DecimalField(max_digits=10, decimal_places=2, default=1)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    tax_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    subtotal = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    class Meta:
        verbose_name = _('Invoice Item')
        verbose_name_plural = _('Invoice Items')

    def __str__(self):
        return f"{self.product.name if self.product else 'Custom Item'} - {self.quantity} @ {self.unit_price} ({self.invoice.invoice_number})"

class Payment(models.Model):
    """Paiements reçus pour les factures"""
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name='payments')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_date = models.DateField()
    payment_method = models.CharField(max_length=50, blank=True, null=True)
    currency = models.CharField(max_length=10, default='XOF')
    transaction_id = models.CharField(max_length=255, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='registered_payments')
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Payment')
        verbose_name_plural = _('Payments')

    def __str__(self):
        return f"Payment for {self.invoice.invoice_number} - {self.amount} ({self.payment_date})"
