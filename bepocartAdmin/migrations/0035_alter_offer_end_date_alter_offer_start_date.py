# Generated by Django 5.0.6 on 2024-07-15 07:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bepocartAdmin', '0034_offer'),
    ]

    operations = [
        migrations.AlterField(
            model_name='offer',
            name='end_date',
            field=models.DateField(),
        ),
        migrations.AlterField(
            model_name='offer',
            name='start_date',
            field=models.DateField(),
        ),
    ]
