from django.db import models

# Create your models here.
class RegisterUser(models.Model):
    username = models.CharField(max_length=20)
    password = models.CharField(max_length=20)


class AnomalyTraffic1(models.Model):
    first_time_stamp = models.CharField(max_length=100)
    last_time_stamp = models.CharField(max_length=100)
    count = models.IntegerField(default=1)
    src_ip = models.CharField(max_length=100)
    dst_ip = models.CharField(max_length=100)
    src_port = models.CharField(max_length=100)
    dst_port = models.CharField(max_length=100)
    anomaly_type = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.src_ip}:{self.src_port} to {self.dst_ip}:{self.dst_port}"
    
class AnomalyTraffic(models.Model):
    first_time_stamp = models.CharField(max_length=100)
    last_time_stamp = models.CharField(max_length=100)
    count = models.IntegerField(default=1)
    src_ip = models.CharField(max_length=100)
    dst_ip = models.CharField(max_length=100)
    src_port = models.CharField(max_length=100)
    dst_port = models.CharField(max_length=100)
    anomaly_type = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.src_ip}:{self.src_port} to {self.dst_ip}:{self.dst_port}"
    

class PcapAnomalyTraffic1(models.Model):
    first_time_stamp = models.CharField(max_length=100)
    last_time_stamp = models.CharField(max_length=100)
    count = models.IntegerField(default=1)
    src_ip = models.CharField(max_length=100)
    dst_ip = models.CharField(max_length=100)
    src_port = models.CharField(max_length=100)
    dst_port = models.CharField(max_length=100)
    anomaly_type = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.src_ip}:{self.src_port} to {self.dst_ip}:{self.dst_port}"
    
class PcapAnomalyTraffic(models.Model):
    first_time_stamp = models.CharField(max_length=100)
    last_time_stamp = models.CharField(max_length=100)
    count = models.IntegerField(default=1)
    src_ip = models.CharField(max_length=100)
    dst_ip = models.CharField(max_length=100)
    src_port = models.CharField(max_length=100)
    dst_port = models.CharField(max_length=100)
    anomaly_type = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.src_ip}:{self.src_port} to {self.dst_ip}:{self.dst_port}"