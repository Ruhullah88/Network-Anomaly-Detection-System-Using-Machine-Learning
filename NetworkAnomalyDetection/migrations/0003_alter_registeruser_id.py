# Generated by Django 4.0.6 on 2023-01-14 14:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('NetworkAnomalyDetection', '0002_alter_registeruser_password_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='registeruser',
            name='id',
            field=models.IntegerField(primary_key=True, serialize=False),
        ),
    ]