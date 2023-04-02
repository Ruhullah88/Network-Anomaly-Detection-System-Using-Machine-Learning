from django.contrib import admin
from .models import AnomalyTraffic, AnomalyTraffic1, PcapAnomalyTraffic, PcapAnomalyTraffic1, RegisterUser

# Register your models here.
admin.site.register(RegisterUser)
admin.site.register(AnomalyTraffic)
admin.site.register(AnomalyTraffic1)
admin.site.register(PcapAnomalyTraffic)
admin.site.register(PcapAnomalyTraffic1)