# Generated by Django 5.0.6 on 2024-07-03 10:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bepocartAdmin', '0019_alter_cart_color_alter_cart_size'),
        ('bepocartBackend', '0020_orderitem_color_orderitem_size'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='coupon',
            name='discount_category',
        ),
        migrations.RemoveField(
            model_name='coupon',
            name='discount_product',
        ),
        migrations.AlterField(
            model_name='coupon',
            name='status',
            field=models.CharField(default='Inactive', max_length=20),
        ),
        migrations.AlterModelTable(
            name='coupon',
            table='Coupon',
        ),
        migrations.AddField(
            model_name='coupon',
            name='discount_category',
            field=models.ManyToManyField(blank=True, to='bepocartAdmin.subcategory'),
        ),
        migrations.AddField(
            model_name='coupon',
            name='discount_product',
            field=models.ManyToManyField(blank=True, to='bepocartAdmin.product'),
        ),
    ]
