import subprocess
import threading
from django.apps import AppConfig
from django.db.models.signals import post_migrate


def startCicFlowMeter():
    thread = threading.Thread(target=cicFlowmeter)
    print("Starting Thread...")
    thread.start()

def cicFlowmeter():
    cmd = 'source ~/.bash_profile'
    command = 'sudo python3 /Library/Frameworks/Python.framework/Versions/3.10/bin/cicflowmeter'
    subprocess.run(cmd, shell=True)
    print("started cicflowmeter")
    subprocess.run(command, shell=True)

def my_handler(sender, **kwargs):
    print("Starting handler...")
    startCicFlowMeter()

class NetworkanomalydetectionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'NetworkAnomalyDetection'
    
    def ready(self):
        print("++++++++++++++++++++++++")
        #post_migrate.connect(my_handler, sender=self)