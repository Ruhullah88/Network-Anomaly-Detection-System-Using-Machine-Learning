
import json
from django.http import JsonResponse
from django.shortcuts import render
from .models import RegisterUser

# importing packages for machine learning
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.multiclass import OneVsOneClassifier
from sklearn.preprocessing import LabelEncoder

import pickle

# importing scapy
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import TCP

from sklearn.metrics import balanced_accuracy_score, precision_score

import warnings
warnings.filterwarnings("ignore")

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def register(request):
    return render(request, "register.html")

def login(request):
    return render(request, "login.html")

def registerAccount(request):
    if request.method == 'POST':
        print(request.POST['username'])
        print(request.POST['password1'])
        print(request.POST['password2'])
        username = request.POST['username']
        pass1 = request.POST['password1']
        pass2 = request.POST['password2']

        # check both password fields are equal and are not empty
        if pass1 != "" and pass2 != "" and (pass1 == pass2):
            if username != "":
                user = RegisterUser(username=username, password=pass1)
                user.save()
                return JsonResponse({"success":"true"})

            else:
                return JsonResponse({"success":"false"})
        else:
            return JsonResponse({"success":"false"})

def loginAccount(request):
    if request.method == 'POST':
        username = request.POST['username']
        passsword = request.POST['password']
        
        if RegisterUser.objects.filter(username=username).exists():

            if RegisterUser.objects.get(username=username).password == passsword:
                return JsonResponse({"Credential":"true"})
            else:
                return JsonResponse({"Credential":"false"})
        else:
            return JsonResponse({"Credential":"false"})

def index(request):
    return render(request, "index.html")

def getPkt(request):
    
    result = {"src_ip":"",
                "dst_ip":"",
                "sport":"",
                "dport":"",
                }
    def predict(packet):
        
        if packet.haslayer(IP):
            src_ip = packet[0][IP].src
            dst_ip = packet[0][IP].dst
            result["src_ip"] = src_ip
            result["dst_ip"] = dst_ip

        if packet.haslayer(TCP):
            sport=packet[0][TCP].sport
            dport= packet[0][TCP].dport
            result["sport"] = sport
            result["dport"] = dport

    sniff(iface="en0", count=5, store=False, prn=predict)
    a = {"sniffed": result}

    return JsonResponse(a)

def anomalyPage(request):
    return render(request, "page1.html")

def malLinkPage(request):
    return render(request, "page2.html")

def trainPage(request):
    return render(request, "page3.html")
    
def statPage(request):
    return render(request, "page4.html")

def trainModel(request):
    
    if request.method == "POST":

        csv_file = request.FILES.get("file")
        df = pd.read_csv(csv_file)

        # features={"Bot":["Bwd Packet Length Mean","Flow IAT Max","Flow Duration","Flow IAT Min","Label"],
        # "DDoS":["Bwd Packet Length Std","Total Backward Packets","Fwd IAT Total","Flow Duration","Label"],
        # "DoS GoldenEye":["Flow IAT Max","Bwd Packet Length Std","Flow IAT Min","Total Backward Packets","Label"],
        # "DoS Hulk":["Bwd Packet Length Std","Fwd Packet Length Std","Fwd Packet Length Max","Flow IAT Min","Label"],
        # "DoS Slowhttptest":["Flow IAT Mean","Fwd Packet Length Min","Bwd Packet Length Mean","Total Length of Bwd Packets","Label"],
        # "DoS slowloris":["Flow IAT Mean","Total Length of Bwd Packets","Bwd Packet Length Mean","Total Fwd Packets","Label"],
        # "FTP-Patator":["Fwd Packet Length Max","Fwd Packet Length Std","Fwd Packet Length Mean","Bwd Packet Length Std","Label"],
        # "Heartbleed":["Total Backward Packets","Fwd Packet Length Max","Flow IAT Min","Bwd Packet Length Max","Label"],
        # "Infiltration":["Fwd Packet Length Max","Fwd Packet Length Mean","Flow Duration","Total Length of Fwd Packets","Label"],
        # "PortScan":["Flow Bytes/s","Total Length of Fwd Packets","Fwd IAT Total","Flow Duration","Label"],
        # "SSH-Patator":["Fwd Packet Length Max","Flow Duration","Flow IAT Max","Total Length of Fwd Packets","Label"],
        # "Web Attack":["Bwd Packet Length Std","Total Length of Fwd Packets","Flow Bytes/s","Flow IAT Max","Label"]}
        
        aa= [[976.0,127.6111111,288.1713418,652,5808851,1978974.0,181526.5937,18.0,534015.4383,5808851.0,640.0,99.73333333,0.0,166.6851037,18,15,2297.0,1496.0]]
        features={"all_data":["Bwd Packet Length Max","Bwd Packet Length Mean","Bwd Packet Length Std","Flow Bytes/s",
        "Flow Duration","Flow IAT Max","Flow IAT Mean","Flow IAT Min","Flow IAT Std","Fwd IAT Total","Fwd Packet Length Max",
        "Fwd Packet Length Mean","Fwd Packet Length Min","Fwds Packet Length Std","Total Backward Packets","Total Fwd Packets",
        "Total Length of Bwd Packets","Total Length of Fwd Packets","Label"]}

        seconds=time.time() #time stamp for all processing time

        df=df.fillna(0)
        print(df["Label"].unique())
        attack_or_not=[]
        for attack in df["Label"]:
            if attack == "BENIGN":
                attack_or_not.append(0)
            else:
                attack_or_not.append(1)
        df["Label"] = attack_or_not
        print(df["Label"].unique())

        feature_list=list(features["all_data"])

        y = df["Label"]
        del df["Label"]
        feature_list.remove('Label')
        X = df[feature_list]

        # cross-validation
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.20, random_state = 10)
        pr = 0
        for i in range(10):
            
            randomfc = RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1)
            randomfc_model = randomfc.fit(X_train, y_train)
            
            pred = randomfc_model.predict(X_test)
            temp_pred=precision_score(y_test, pred, average='macro')
            
            if (temp_pred > pr):
                pr = temp_pred
                model = randomfc_model
        
        print(pr)
        
        print("prediction: ", model.predict(aa))
        
        
        filename = '../../all.sav'
        pickle.dump(model, open(filename, 'wb'))

        return JsonResponse({
            "success": "true",})

    # elif request.method == "GET":
    #     print("Get Method")
    #     return JsonResponse({
    #         "success": "success",
    #         "time": time_taken,        
    #         })
    else:
        return render(request, "page3.html")

def postFeatures(request):
    if (request.method == "POST"):
        print("adsf")