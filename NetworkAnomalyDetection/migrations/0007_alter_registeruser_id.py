# Generated by Django 4.0.6 on 2023-01-14 15:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('NetworkAnomalyDetection', '0006_alter_registeruser_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='registeruser',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]
