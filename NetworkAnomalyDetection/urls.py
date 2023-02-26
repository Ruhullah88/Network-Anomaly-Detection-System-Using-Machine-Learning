
from django.urls import path
from . import views

urlpatterns = [
    #path('', views.register, name="register"),

    path('anomalyPage', views.anomalyPage, name="anomalyPage"),
    
    #path('index', views.index, name="index"),
    path('', views.index, name="index"),
    path('trainPage', views.trainPage, name="trainPage"),
    path('malLinkPage', views.malLinkPage, name="malLinkPage"),
    path('statPage', views.statPage, name="statPage"),

    path('getPkt', views.getPkt, name="getPkt"),
    path('trainModel', views.trainModel, name="trainModel"),
    path('postFeatures', views.postFeatures, name="postFeatures"),
    path('registerAccount', views.registerAccount, name="registerAccount"),
    
    path('login', views.login, name="login"),
    path('loginAccount', views.loginAccount, name="loginAccount"),

]