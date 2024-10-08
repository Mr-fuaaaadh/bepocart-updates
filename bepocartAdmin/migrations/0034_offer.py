# Generated by Django 5.0.6 on 2024-07-15 05:49

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bepocartAdmin', '0033_remove_product_offer_banner_and_more'),
        ('bepocartBackend', '0026_review_status'),
    ]

    operations = [
        migrations.CreateModel(
            name='Offer',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('buy', models.CharField(max_length=100)),
                ('get', models.CharField(max_length=100)),
                ('get_value', models.IntegerField(max_length=100)),
                ('method', models.CharField(max_length=100)),
                ('discount_percentage', models.DecimalField(blank=True, decimal_places=2, max_digits=5, null=True, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(100)])),
                ('start_date', models.DateTimeField()),
                ('end_date', models.DateTimeField()),
                ('messages', models.CharField(max_length=500, null=True)),
                ('coupon_use_limit', models.IntegerField()),
                ('coupon_use_order_limit', models.IntegerField()),
                ('shipping_charge', models.IntegerField(default=0)),
                ('categories', models.ManyToManyField(blank=True, related_name='offers', to='bepocartAdmin.subcategory')),
                ('exclude_categories', models.ManyToManyField(blank=True, related_name='exclude_categories', to='bepocartAdmin.subcategory')),
                ('exclude_products', models.ManyToManyField(blank=True, related_name='exclude_products', to='bepocartAdmin.product')),
                ('not_allowed_coupons', models.ManyToManyField(blank=True, to='bepocartBackend.coupon')),
                ('products', models.ManyToManyField(blank=True, related_name='offers', to='bepocartAdmin.product')),
            ],
        ),
    ]
