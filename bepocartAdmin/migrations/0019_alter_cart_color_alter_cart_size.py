# Generated by Django 5.0.6 on 2024-06-22 07:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bepocartAdmin', '0018_cart_color_cart_size'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cart',
            name='color',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='cart',
            name='size',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
