# Generated by Django 5.0.6 on 2024-06-04 05:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bepocartAdmin', '0010_delete_admin'),
    ]

    operations = [
        migrations.CreateModel(
            name='OfferBanner',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('image', models.ImageField(upload_to='offer_banner')),
            ],
            options={
                'db_table': 'Offer_Banner',
            },
        ),
    ]
