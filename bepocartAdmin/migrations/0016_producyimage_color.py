# Generated by Django 5.0.6 on 2024-06-10 06:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bepocartAdmin', '0015_producyimage'),
    ]

    operations = [
        migrations.AddField(
            model_name='producyimage',
            name='color',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
