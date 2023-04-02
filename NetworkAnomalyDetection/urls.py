
from django.urls import path
from . import views

urlpatterns = [
    path('', views.register, name="register"),

    path('anomalyPage', views.anomalyPage, name="anomalyPage"),
    path('anomaly_data', views.anomaly_data, name="anomaly_data"),
    
    path('index', views.index, name="index"),
    #path('', views.index, name="index"),
    path('trainPage', views.trainPage, name="trainPage"),
    path('malLinkPage', views.malLinkPage, name="malLinkPage"),
    path('statPage', views.statPage, name="statPage"),

    path('getPkt', views.getPkt, name="getPkt"),
    path('trainModel', views.trainModel, name="trainModel"),
    path('predict', views.predict, name="predict"),
    path('generate_report', views.generate_report, name="generate_report"),
    path('get_anomaly_details', views.get_anomaly_details, name="get_anomaly_details"),

    path('registerAccount', views.registerAccount, name="registerAccount"),
    
    path('login', views.login, name="login"),
    path('loginAccount', views.loginAccount, name="loginAccount"),
    
    # pcap
    path('get_pcap_anomaly_details', views.get_pcap_anomaly_details, name="get_pcap_anomaly_details"),
    path('pcap_anomaly_data', views.pcap_anomaly_data, name="pcap_anomaly_data"),
    path('upload_pcap', views.upload_pcap, name="upload_pcap"),
]

