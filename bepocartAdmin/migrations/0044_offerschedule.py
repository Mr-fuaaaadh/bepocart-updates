# Generated by Django 5.0.6 on 2024-07-17 04:58

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bepocartAdmin', '0043_delete_offer'),
        ('bepocartBackend', '0026_review_status'),
    ]

    operations = [
        migrations.CreateModel(
            name='OfferSchedule',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('offer_type', models.CharField(help_text='Select BUY or SPEND', max_length=100)),
                ('amount', models.IntegerField(blank=True, help_text='Amount for BUY or SPEND', null=True)),
                ('get_option', models.CharField(help_text='Option for GET', max_length=100)),
                ('get_value', models.IntegerField(blank=True, help_text='Free quantity', null=True)),
                ('method', models.CharField(help_text='Select FREE or % OFF', max_length=100)),
                ('discount_percentage', models.DecimalField(blank=True, decimal_places=2, help_text='Discount percentage if method is % OFF', max_digits=5, null=True, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(100)])),
                ('start_date', models.DateField(help_text='Start date of the offer')),
                ('end_date', models.DateField(help_text='End date of the offer')),
                ('messages', models.CharField(help_text='Additional messages for the offer', max_length=500, null=True)),
                ('coupon_user_limit', models.IntegerField(blank=True, help_text='Maximum usage per user for coupons', null=True)),
                ('coupon_use_order_limit', models.IntegerField(blank=True, help_text='Maximum usage per order for coupons', null=True)),
                ('shipping_charge', models.IntegerField(default=0, help_text='Shipping charge applicable with the offer')),
                ('is_active', models.CharField(default='Allowed', help_text='Active status of the offer', max_length=200)),
                ('discount_approved_category', models.ManyToManyField(blank=True, help_text='Categories approved for discount', related_name='approved_offers', to='bepocartAdmin.category')),
                ('discount_approved_products', models.ManyToManyField(blank=True, help_text='Products approved for discount', related_name='approved_offers', to='bepocartAdmin.product')),
                ('discount_not_allowed_category', models.ManyToManyField(blank=True, help_text='Categories not allowed for discount', related_name='not_allowed_offers', to='bepocartAdmin.category')),
                ('discount_not_allowed_products', models.ManyToManyField(blank=True, help_text='Products not allowed for discount', related_name='not_allowed_offers', to='bepocartAdmin.product')),
                ('exclude_products', models.ManyToManyField(blank=True, help_text='Products excluded from this offer', related_name='exclude_offers', to='bepocartAdmin.product')),
                ('excluded_offer_category', models.ManyToManyField(blank=True, help_text='Categories excluded from this offer', related_name='exclude_offers', to='bepocartAdmin.subcategory')),
                ('not_allowed_coupons', models.ManyToManyField(blank=True, help_text='Coupons not allowed with this offer', to='bepocartBackend.coupon')),
                ('offer_category', models.ManyToManyField(blank=True, help_text='Categories eligible for this offer', related_name='offers', to='bepocartAdmin.subcategory')),
                ('offer_products', models.ManyToManyField(blank=True, help_text='Products eligible for this offer', related_name='offers', to='bepocartAdmin.product')),
            ],
            options={
                'db_table': 'Offer',
            },
        ),
    ]
