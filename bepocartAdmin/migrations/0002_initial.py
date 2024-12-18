# Generated by Django 5.1.3 on 2024-11-29 05:11

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('bepocartAdmin', '0001_initial'),
        ('bepocartBackend', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='cart',
            name='customer',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bepocartBackend.customer'),
        ),
        migrations.AddField(
            model_name='coin',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bepocartBackend.customer'),
        ),
        migrations.AddField(
            model_name='offerschedule',
            name='not_allowed_coupons',
            field=models.ManyToManyField(blank=True, help_text='Coupons not allowed with this offer', to='bepocartBackend.coupon'),
        ),
        migrations.AddField(
            model_name='offerschedule',
            name='discount_approved_products',
            field=models.ManyToManyField(blank=True, help_text='Products approved for discount', related_name='approved_offers', to='bepocartAdmin.product'),
        ),
        migrations.AddField(
            model_name='offerschedule',
            name='discount_not_allowed_products',
            field=models.ManyToManyField(blank=True, help_text='Products not allowed for discount', related_name='not_allowed_offers', to='bepocartAdmin.product'),
        ),
        migrations.AddField(
            model_name='offerschedule',
            name='exclude_products',
            field=models.ManyToManyField(blank=True, help_text='Products excluded from this offer', related_name='exclude_offers', to='bepocartAdmin.product'),
        ),
        migrations.AddField(
            model_name='offerschedule',
            name='offer_products',
            field=models.ManyToManyField(blank=True, help_text='Products eligible for this offer', related_name='offers', to='bepocartAdmin.product'),
        ),
        migrations.AddField(
            model_name='cart',
            name='product',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bepocartAdmin.product'),
        ),
        migrations.AddField(
            model_name='productcolorstock',
            name='product',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='color_stocks', to='bepocartAdmin.product'),
        ),
        migrations.AddField(
            model_name='productvariant',
            name='product',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='variants', to='bepocartAdmin.product'),
        ),
        migrations.AddField(
            model_name='productvarientsizestock',
            name='product_variant',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='size_stocks', to='bepocartAdmin.productvariant'),
        ),
        migrations.AddField(
            model_name='subcategory',
            name='category',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='subcategories', to='bepocartAdmin.category'),
        ),
        migrations.AddField(
            model_name='product',
            name='category',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='products', to='bepocartAdmin.subcategory'),
        ),
        migrations.AddField(
            model_name='offerschedule',
            name='discount_approved_category',
            field=models.ManyToManyField(blank=True, help_text='Categories approved for discount', related_name='approved_offers', to='bepocartAdmin.subcategory'),
        ),
        migrations.AddField(
            model_name='offerschedule',
            name='discount_not_allowed_category',
            field=models.ManyToManyField(blank=True, help_text='Categories not allowed for discount', related_name='not_allowed_offers', to='bepocartAdmin.subcategory'),
        ),
        migrations.AddField(
            model_name='offerschedule',
            name='excluded_offer_category',
            field=models.ManyToManyField(blank=True, help_text='Categories excluded from this offer', related_name='exclude_offers', to='bepocartAdmin.subcategory'),
        ),
        migrations.AddField(
            model_name='offerschedule',
            name='offer_category',
            field=models.ManyToManyField(blank=True, help_text='Categories eligible for this offer', related_name='offers', to='bepocartAdmin.subcategory'),
        ),
        migrations.AddField(
            model_name='carousal',
            name='category',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='bepocartAdmin.subcategory'),
        ),
        migrations.AddField(
            model_name='wishlist',
            name='product',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bepocartAdmin.product'),
        ),
        migrations.AddField(
            model_name='wishlist',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bepocartBackend.customer'),
        ),
        migrations.AlterUniqueTogether(
            name='productcolorstock',
            unique_together={('product', 'color')},
        ),
        migrations.AddIndex(
            model_name='product',
            index=models.Index(fields=['name'], name='product_name_c4c985_idx'),
        ),
    ]
