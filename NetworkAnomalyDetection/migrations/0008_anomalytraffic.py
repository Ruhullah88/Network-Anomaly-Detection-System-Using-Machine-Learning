# Generated by Django 4.0.6 on 2023-03-08 08:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('NetworkAnomalyDetection', '0007_alter_registeruser_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='AnomalyTraffic',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('time_stamp', models.CharField(max_length=100)),
                ('src_ip', models.CharField(max_length=100)),
                ('dst_ip', models.CharField(max_length=100)),
                ('src_port', models.CharField(max_length=100)),
                ('dst_port', models.CharField(max_length=100)),
                ('anomaly_type', models.CharField(max_length=100)),
            ],
        ),
    ]
