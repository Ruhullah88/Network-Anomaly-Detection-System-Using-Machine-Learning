# Generated by Django 4.0.6 on 2023-01-14 15:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('NetworkAnomalyDetection', '0004_alter_registeruser_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='registeruser',
            name='id',
            field=models.UUIDField(primary_key=True, serialize=False),
        ),
    ]
