
import pickle
import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score
from sklearn.model_selection import train_test_split
from sklearn.multioutput import MultiOutputClassifier
from sklearn.neighbors import KNeighborsClassifier

import warnings
warnings.filterwarnings("ignore")


df = pd.read_csv("/Users/ruhullahansari88/Desktop/Network Anomaly Detection/Final Year Project/all_data.csv")

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

feature_list=list(features["all_data"])

y = df["Label"]
del df["Label"]
feature_list.remove('Label')
X = df[feature_list]

# cross-validation
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.20, random_state = 10)
pr = 0
for i in range(1):
    
    randomfc = MultiOutputClassifier(RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1))
    randomfc_model = randomfc.fit(X_train, y_train)
    
    pred = randomfc_model.predict(X_test)
    temp_pred=precision_score(y_test, pred, average='macro')
    
    if (temp_pred > pr):
        pr = temp_pred
        model = randomfc_model

print(pr)



filename = 'Models/model.sav'
pickle.dump(model, open(filename, 'wb'))
