
import json
from django.http import FileResponse, HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import render

from .models import AnomalyTraffic, AnomalyTraffic1, PcapAnomalyTraffic, PcapAnomalyTraffic1, RegisterUser
from django.conf import settings

from django.http import HttpResponse
from reportlab.lib.pagesizes import letter, portrait
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph

from django.db.models import F, ExpressionWrapper, fields
from django.core.serializers.json import DjangoJSONEncoder
from itertools import chain
from datetime import datetime, timedelta

from .Generate_report import create_pdf

from django.views.decorators.clickjacking import xframe_options_exempt



# Cicflowmeter
from cicflowmeter.sniffer import create_sniffer


# importing packages for machine learning
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

import pickle
from django.views.decorators.csrf import csrf_exempt

# importing scapy
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP

from sklearn.metrics import precision_score

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
    result = {
        "time":"",
        "src_ip":"",
                "sport":"",
                "dst_ip":"",
                "dport":"",
                "protocol":"",

                }
    def predict(packet):
        
        if packet.haslayer(IP):
            src_ip = packet[0][IP].src
            dst_ip = packet[0][IP].dst

            capture_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))

            result["time"] = capture_time
            result["src_ip"] = src_ip
            result["dst_ip"] = dst_ip
            result["Protocol"] = "IP"

        elif packet.haslayer(TCP):
            sport=packet[0][TCP].sport
            dport= packet[0][TCP].dport

            capture_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))

            result["time"] = capture_time
            result["sport"] = sport
            result["dport"] = dport
            result["protocol"] = "TCP"

        elif packet.haslayer(UDP):
            sport=packet[0][UDP].sport
            dport= packet[0][UDP].dport

            capture_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))

            result["time"] = capture_time
            result["sport"] = sport
            result["dport"] = dport
            result["protocol"] = "UDP"

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

@csrf_exempt
def predict(request):
    if request.method == 'POST':
        csv_data = request.body

        json_data = json.loads(csv_data.decode('utf-8'))
        traffic_list = json_data['data'][0]
        index_to_extract = [19,21,22,7,6,33,32,34,35,36,15,17,16,12,11,14,13]
        #index_to_extract = [21,23,24,9,8,35,34,36,37,38,17,19,18,14,13,16,15]
        traffic_list_for_prediction = [traffic_list[i] for i in index_to_extract]
        with open("/Users/ruhullahansari88/Desktop/Network Anomaly Detection/Final Year Project/Models/anomaly_prediction_model_1.sav", "rb") as file:
            clf_loaded = pickle.load(file)

        # Make predictions on the test data using the selected features
        y_pred = clf_loaded.predict([traffic_list_for_prediction])
        print(y_pred[0][0])
        print(traffic_list[7])
        if y_pred[0][0] != 'BENIGN':
            
            settings.CONFIRMATION+=1
            if settings.CONFIRMATION >= 1:

                time_stamp = traffic_list[7]
                src_ip = traffic_list[0]
                dst_ip = traffic_list[1]
                src_port = traffic_list[2]
                dst_port = traffic_list[3]
                anomaly_type = y_pred[0][0]
                #obj, created = AnomalyTraffic.objects.update_or_create(time_stamp=time_stamp, count=1, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, anomaly_type=anomaly_type)
                

                obj = AnomalyTraffic1.objects.filter(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, anomaly_type=anomaly_type)
                if y_pred[0][0] == 'SSH-Patator':
                    obj1 = AnomalyTraffic.objects.filter(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, anomaly_type=anomaly_type)
                    if obj1:
                        obj1[0].count += 1
                        obj1[0].last_time_stamp = time_stamp
                        obj1[0].save()
                        refineAnomaly()
                    else:
                        # Do something if the record does not exist
                        obj1 = AnomalyTraffic(first_time_stamp=time_stamp, last_time_stamp=time_stamp, count=1, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, anomaly_type=anomaly_type)
                        obj1.save()
                else:
                    if obj:
                        obj[0].count += 1
                        obj[0].last_time_stamp = time_stamp
                        obj[0].save()
                        refineAnomaly()
                    else:
                        # Do something if the record does not exist
                        obj = AnomalyTraffic1(first_time_stamp=time_stamp, last_time_stamp=time_stamp, count=1, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, anomaly_type=anomaly_type)
                        obj.save()
                    
                    settings.CONFIRMATION=0
                #sendMail.sendAlert(y_pred[0])

        else:
            settings.CONFIRMATION=0
        
        # process the CSV data here
        return HttpResponse("Data received")
    else:
        return HttpResponseBadRequest("Invalid request method")
from django.db.models import Sum


def refineAnomaly():
    anomaly = AnomalyTraffic1.objects.all()
    for my_model_instance in anomaly:
        #print(datetime.strptime(my_model_instance.last_time_stamp, '%H:%M:%S') - datetime.strptime(my_model_instance.first_time_stamp, '%H:%M:%S'))
        last_date_obj = datetime.strptime(my_model_instance.last_time_stamp.split(" ")[1], '%H:%M:%S')
        first_date_obj = datetime.strptime(my_model_instance.first_time_stamp.split(" ")[1], '%H:%M:%S')
        time_diff = last_date_obj - first_date_obj
        total_seconds = time_diff.total_seconds()
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        if ((minutes > 5) and (my_model_instance.count >=50)) or ((minutes <= 5) and (my_model_instance.count >=50)):
            #obj, created = AnomalyTraffic.objects.update_or_create(time_stamp=time_stamp, count=1, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, anomaly_type=anomaly_type)
            obj = AnomalyTraffic.objects.filter(src_ip=my_model_instance.src_ip, dst_ip=my_model_instance.dst_ip, dst_port=my_model_instance.dst_port, anomaly_type=my_model_instance.anomaly_type)
            print(my_model_instance.count)
            if not obj:
                # Do something if the record does not exist
                obj = AnomalyTraffic(first_time_stamp=my_model_instance.first_time_stamp, last_time_stamp=my_model_instance.last_time_stamp, count=my_model_instance.count, src_ip=my_model_instance.src_ip, dst_ip=my_model_instance.dst_ip, src_port=my_model_instance.src_port, dst_port=my_model_instance.dst_port, anomaly_type=my_model_instance.anomaly_type)
                obj.save()
            else:
                obj.update(first_time_stamp=my_model_instance.first_time_stamp, last_time_stamp=my_model_instance.last_time_stamp, count=my_model_instance.count, src_ip=my_model_instance.src_ip, dst_ip=my_model_instance.dst_ip, src_port=my_model_instance.src_port, dst_port=my_model_instance.dst_port, anomaly_type=my_model_instance.anomaly_type)


def anomaly_data(request):
    anomaly = AnomalyTraffic.objects.all()
    # Use the distinct method to get the unique values of the column
    values_list = list(anomaly.values('src_ip', 'src_port', 'dst_ip', 'dst_port', 'first_time_stamp', 'last_time_stamp', 'count',  'anomaly_type'))

    context={"anomaly":values_list}

    return JsonResponse(context, safe=False)


# get maximum of top 10 value from database
def max_count_names(context):
    # Query the database for the top 10 names by count
    top_names = AnomalyTraffic.objects.order_by('count')[:10]

    # Create a list of dictionaries with the name and count for each top name
    context= context
    result_list = []
    for name in top_names:
        result_list.append({'name': name.context, 'count': name.count})

    # Render a template with the result list
    return result_list


def generate_report(request):
    
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="report.pdf"'
    dict_of_content={}
    if request.method == 'POST':

    
        content = str(request.body.decode('utf-8')).replace("+", " ").split("=")[-1]

        first_time_stamp = content.split(" to ")[0]
        first_time_stamp = datetime.strptime(first_time_stamp, '%Y-%m-%d')
        last_time_stamp = content.split(" to ")[1]
        last_time_stamp = datetime.strptime(last_time_stamp, '%Y-%m-%d')
        
        targated_ip = []
        attack_info=[]
        
        # get the time and total count from the row
        start_time = first_time_stamp
        end_time = last_time_stamp
        interval = timedelta(minutes=25)

        current_time = start_time
        results = []

        while current_time < end_time:
            # Calculate the end time for the current interval
            interval_end = current_time + interval
            
            # Query the database for the sum of the count within the current interval
            interval_count = AnomalyTraffic.objects.filter(first_time_stamp__gte=current_time, first_time_stamp__lt=interval_end).aggregate(Sum('count'))['count__sum']
            
            if interval_count is not None:
                results.append((current_time, interval_count))
            else:
                results.append((current_time, 0))

            # Move to the next interval
            current_time = interval_end

        # Print the results
        result = {dt.strftime("%Y-%m-%d %H:%M:%S"): count for dt, count in results}
        all = AnomalyTraffic.objects.filter(first_time_stamp__range=(first_time_stamp, last_time_stamp))
        for obj in all:
            anomaly = obj.anomaly_type
            start_date = obj.first_time_stamp
            src_ip = obj.src_ip
            dst_ip = obj.dst_ip
            dst_port = obj.dst_port
            count = obj.count

            l =[]
            l.append(anomaly)
            l.append(start_date)
            l.append(src_ip)
            l.append(dst_ip)
            l.append(dst_port)
            l.append(count)

            attack_info.append(l)
            targated_ip.append(dst_ip)

        targated_ip = list(set(targated_ip))

        dict_of_content= {"report_time_peroid":content,
        "targated_ip":targated_ip,
            "attack_info":attack_info,
            "time_stamp":result,}
        
        pdf_bytes =  create_pdf(dict_of_content)
        response = HttpResponse(pdf_bytes.getvalue(), content_type='application/pdf')
        response['Content-Disposition'] = 'inline; filename="report.pdf"'

        return response


def get_anomaly_details(request):

    data = AnomalyTraffic.objects.all()
    total = data.values('anomaly_type').annotate(total_count=Sum('count'))
    data_to_send = list(sorted(total, key=lambda x: x['total_count'], reverse=True))
    send = []
    
    if len(data_to_send) > 3:
        send.append(data_to_send[0])
        send.append(data_to_send[1])
        send.append(data_to_send[2])
        a = data_to_send[3:]
        tot = 0
        for b in a:
            tot = tot+b['total_count']
        send.append({"anomaly_type":"Others","total_count":tot})
    else:
        send = data_to_send

    top_src_ips = list(AnomalyTraffic.objects.values('src_ip').annotate(total_count=Sum('count')).order_by('-total_count')[:10])
    top_src_port_ips = list(AnomalyTraffic.objects.values('src_port').annotate(total_count=Sum('count')).order_by('-total_count')[:10])
    top_dst_ips = list(AnomalyTraffic.objects.values('dst_ip').annotate(total_count=Sum('count')).order_by('-total_count')[:10])
    top_dst_port_ips = list(AnomalyTraffic.objects.values('dst_port').annotate(total_count=Sum('count')).order_by('-total_count')[:10])

    all_table_values = []

    all_table_values.append(top_src_ips)
    all_table_values.append(top_src_port_ips)
    all_table_values.append(top_dst_ips)
    all_table_values.append(top_dst_port_ips)


    context = {"anomaly_count": send, "table_data":all_table_values, "pie_chart_values": data_to_send}
    json_data = json.dumps(context, cls=DjangoJSONEncoder)
    return JsonResponse(json_data, safe=False)



def get_pcap_anomaly_details(request):

    data = PcapAnomalyTraffic.objects.all()
    total = data.values('anomaly_type').annotate(total_count=Sum('count'))
    data_to_send = list(sorted(total, key=lambda x: x['total_count'], reverse=True))
    send = []
    
    if len(data_to_send) > 3:
        send.append(data_to_send[0])
        send.append(data_to_send[1])
        send.append(data_to_send[2])
        a = data_to_send[3:]
        tot = 0
        for b in a:
            tot = tot+b['total_count']
        send.append({"anomaly_type":"Others","total_count":tot})
    else:
        send = data_to_send

    top_src_ips = list(PcapAnomalyTraffic.objects.values('src_ip').annotate(total_count=Sum('count')).order_by('-total_count')[:10])
    top_src_port_ips = list(PcapAnomalyTraffic.objects.values('src_port').annotate(total_count=Sum('count')).order_by('-total_count')[:10])
    top_dst_ips = list(PcapAnomalyTraffic.objects.values('dst_ip').annotate(total_count=Sum('count')).order_by('-total_count')[:10])
    top_dst_port_ips = list(PcapAnomalyTraffic.objects.values('dst_port').annotate(total_count=Sum('count')).order_by('-total_count')[:10])

    all_table_values = []

    all_table_values.append(top_src_ips)
    all_table_values.append(top_src_port_ips)
    all_table_values.append(top_dst_ips)
    all_table_values.append(top_dst_port_ips)


    context = {"anomaly_count": send, "table_data":all_table_values, "pie_chart_values": data_to_send}
    json_data = json.dumps(context, cls=DjangoJSONEncoder)
    return JsonResponse(json_data, safe=False)


def pcap_anomaly_data(request):
    anomaly = PcapAnomalyTraffic.objects.all()
    # Use the distinct method to get the unique values of the column
    values_list = list(anomaly.values('src_ip', 'src_port', 'dst_ip', 'dst_port', 'first_time_stamp', 'last_time_stamp', 'count',  'anomaly_type'))

    context={"anomaly":values_list}

    return JsonResponse(context, safe=False)

def refinePcapAnomaly():
    anomaly = PcapAnomalyTraffic1.objects.all()
    for my_model_instance in anomaly:
        #print(datetime.strptime(my_model_instance.last_time_stamp, '%H:%M:%S') - datetime.strptime(my_model_instance.first_time_stamp, '%H:%M:%S'))
        last_date_obj = datetime.strptime(my_model_instance.last_time_stamp.split(" ")[1], '%H:%M:%S')
        first_date_obj = datetime.strptime(my_model_instance.first_time_stamp.split(" ")[1], '%H:%M:%S')
        time_diff = last_date_obj - first_date_obj
        total_seconds = time_diff.total_seconds()
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        if ((minutes > 5) and (my_model_instance.count >=50)) or ((minutes <= 5) and (my_model_instance.count >=50)):
            #obj, created = AnomalyTraffic.objects.update_or_create(time_stamp=time_stamp, count=1, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, anomaly_type=anomaly_type)
            obj = PcapAnomalyTraffic.objects.filter(src_ip=my_model_instance.src_ip, dst_ip=my_model_instance.dst_ip, dst_port=my_model_instance.dst_port, anomaly_type=my_model_instance.anomaly_type)
            print(my_model_instance.count)
            if not obj:
                # Do something if the record does not exist
                obj = PcapAnomalyTraffic(first_time_stamp=my_model_instance.first_time_stamp, last_time_stamp=my_model_instance.last_time_stamp, count=my_model_instance.count, src_ip=my_model_instance.src_ip, dst_ip=my_model_instance.dst_ip, src_port=my_model_instance.src_port, dst_port=my_model_instance.dst_port, anomaly_type=my_model_instance.anomaly_type)
                obj.save()
            else:
                obj.update(first_time_stamp=my_model_instance.first_time_stamp, last_time_stamp=my_model_instance.last_time_stamp, count=my_model_instance.count, src_ip=my_model_instance.src_ip, dst_ip=my_model_instance.dst_ip, src_port=my_model_instance.src_port, dst_port=my_model_instance.dst_port, anomaly_type=my_model_instance.anomaly_type)




from .cicflowmeter.src.cicflowmeter.sniffer import main
def upload_pcap(request):

    if request.method == 'POST':
        uploaded_file = request.FILES['my_file']
        main(uploaded_file.read() ,None)
        print("------------------completed------------------")
        # do something with the uploaded file
        return HttpResponse('File uploaded successfully.')
    return render(request, 'page2.html')
