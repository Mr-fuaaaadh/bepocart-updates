# Generated by Django 5.0.6 on 2024-06-14 05:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bepocartBackend', '0006_orderitem_customer'),
    ]

    operations = [
        migrations.AddField(
            model_name='customer',
            name='image',
            field=models.ImageField(null=True, upload_to='UserProfile'),
        ),
    ]
