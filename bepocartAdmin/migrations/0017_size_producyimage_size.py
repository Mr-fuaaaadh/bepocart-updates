# Generated by Django 5.0.6 on 2024-06-13 04:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bepocartAdmin', '0016_producyimage_color'),
    ]

    operations = [
        migrations.CreateModel(
            name='Size',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'Size',
            },
        ),
        migrations.AddField(
            model_name='producyimage',
            name='size',
            field=models.ManyToManyField(to='bepocartAdmin.size'),
        ),
    ]
