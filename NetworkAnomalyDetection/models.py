from django.db import models

# Create your models here.
class RegisterUser(models.Model):
    username = models.CharField(max_length=20)
    password = models.CharField(max_length=20)
