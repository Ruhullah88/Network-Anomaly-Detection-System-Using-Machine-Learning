# Generated by Django 4.0.6 on 2023-01-14 14:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('NetworkAnomalyDetection', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='registeruser',
            name='password',
            field=models.CharField(max_length=20),
        ),
        migrations.AlterField(
            model_name='registeruser',
            name='username',
            field=models.CharField(max_length=20),
        ),
    ]
