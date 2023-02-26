
import pickle
import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier

import warnings
warnings.filterwarnings("ignore")


df = pd.read_csv("/Users/ruhullahansari88/Desktop/Network Anomaly Detection/Final Year Project/all_data.csv")

aa= [[976.0,127.6111111,288.1713418,652,5808851,1978974.0,181526.5937,18.0,534015.4383,5808851.0,640.0,99.73333333,0.0,18,15,2297.0,1496.0]]

features={"all_data":["Bwd Packet Length Max","Bwd Packet Length Mean","Bwd Packet Length Std","Flow Bytes/s",
"Flow Duration","Flow IAT Max","Flow IAT Mean","Flow IAT Min","Flow IAT Std","Fwd IAT Total","Fwd Packet Length Max",
"Fwd Packet Length Mean","Fwd Packet Length Min","Total Backward Packets","Total Fwd Packets",
"Total Length of Bwd Packets","Total Length of Fwd Packets","Label"]}

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
for i in range(1):
    
    randomfc = RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1)
    randomfc_model = randomfc.fit(X_train, y_train)
    
    pred = randomfc_model.predict(X_test)
    temp_pred=precision_score(y_test, pred, average='macro')
    
    if (temp_pred > pr):
        pr = temp_pred
        model = randomfc_model

print(pr)

print("prediction: ", model.predict(aa))


filename = 'model.sav'
pickle.dump(model, open(filename, 'wb'))
