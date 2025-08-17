from django.db import models
from django.utils.translation import gettext_lazy as _
from companies.models import Company

class Product(models.Model):
    """Produits et services proposés par les entreprises"""
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='products')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Product')
        verbose_name_plural = _('Products')

    def __str__(self):
        return f"{self.name} - {self.unit_price} ({self.company.name})"

class ProductCategory(models.Model):
    """Catégories de produits pour une meilleure organisation"""
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='product_categories')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Product Category')
        verbose_name_plural = _('Product Categories')

    def __str__(self):
        return f"{self.name} ({self.company.name})"
