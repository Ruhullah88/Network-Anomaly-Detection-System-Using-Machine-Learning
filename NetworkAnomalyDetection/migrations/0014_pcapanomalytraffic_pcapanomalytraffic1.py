# Generated by Django 4.0.6 on 2023-03-23 06:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('NetworkAnomalyDetection', '0013_anomalytraffic1'),
    ]

    operations = [
        migrations.CreateModel(
            name='PcapAnomalyTraffic',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_time_stamp', models.CharField(max_length=100)),
                ('last_time_stamp', models.CharField(max_length=100)),
                ('count', models.IntegerField(default=1)),
                ('src_ip', models.CharField(max_length=100)),
                ('dst_ip', models.CharField(max_length=100)),
                ('src_port', models.CharField(max_length=100)),
                ('dst_port', models.CharField(max_length=100)),
                ('anomaly_type', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='PcapAnomalyTraffic1',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_time_stamp', models.CharField(max_length=100)),
                ('last_time_stamp', models.CharField(max_length=100)),
                ('count', models.IntegerField(default=1)),
                ('src_ip', models.CharField(max_length=100)),
                ('dst_ip', models.CharField(max_length=100)),
                ('src_port', models.CharField(max_length=100)),
                ('dst_port', models.CharField(max_length=100)),
                ('anomaly_type', models.CharField(max_length=100)),
            ],
        ),
    ]
