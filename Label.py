#!/usr/bin/env python
# coding: utf-8

import pandas as pd
import numpy as np
import re

df = pd.read_csv("urldata.csv")
df.head()

df.isnull().sum()

def operation(df):
    # Generating Features for the detection
    df['NumDots'] = df['url'].apply(lambda x: len(x.split(".")) -1)

    # Length of Url
    df['urlLength'] = df['url'].apply(lambda x: len(x))

    # Character Letter in URL
    df['CharacterletterCount'] = df['url'].apply(lambda x: len("".join(re.findall(r'[a-zA-Z]+', x))))

    # Number Letter in URL
    df['CharacterletterCount'] = df['url'].apply(lambda x: len("".join(re.findall(r'[0-9]+', x))))

    # Number of Dash in URL
    df['NumDash'] = df['url'].apply(lambda x: len(x.split("-")) -1)

    # Number of NumDashInHostname in URL
    df['NumDashInHostname'] = df['url'].apply(lambda x: len(x.replace("https://", "").replace("http://","").split("-")) -1)

    # 
    df['count-'] = df['url'].apply(lambda x: x.count('-'))

    # At Symbol Count
    df['AtSymbol'] = df['url'].apply(lambda x: x.count('@'))

    # Tilde Symbol Count
    df['TildeSymbol'] = df['url'].apply(lambda x: x.count('~'))

    # ? Symbol Count
    df['NumQuestionMark'] = df['url'].apply(lambda x: x.count('?'))

    # % Symbol Count
    df['NumModule'] = df['url'].apply(lambda x: x.count('%'))

    # Dot  Symbol Count
    df['NumDot'] = df['url'].apply(lambda x: x.count('.'))

    # equal Symbol Count
    df['NumEqual'] = df['url'].apply(lambda x: x.count('='))

    # & Symbol Count
    df['NumAmpersand'] = df['url'].apply(lambda x: x.count('&'))

    # & Symbol Count
    df['NumAmpersand'] = df['url'].apply(lambda x: x.count('#'))

    # http Count
    df['Numhttp'] = df['url'].apply(lambda x : x.count('http'))

    # https Symbol Count
    df['Numhttps'] = df['url'].apply(lambda x : x.count('https'))

    # www Symbol Count
    df['Numwww'] = df['url'].apply(lambda x: x.count('www'))
    
    #Use of IP or not in domain
    def having_ip_address(url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
        if match:
            return -1
        else:
            return 1

    df['use_of_ip'] = df['url'].apply(lambda x: having_ip_address(x))
    
    return df


df = operation(df)

#from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from sklearn.metrics import confusion_matrix,classification_report,accuracy_score

# InDependent Variable
X = df[['NumDots', 'urlLength', 'NumDash',
       'CharacterletterCount', 'NumDashInHostname', 'count-', 'AtSymbol',
       'TildeSymbol', 'NumQuestionMark', 'NumModule', 'NumDot', 'NumEqual',
       'NumAmpersand', 'Numhttp', 'Numhttps', 'Numwww', 'use_of_ip']]

#Dependent Variable
Y = df['result']

# !pip install sklearn
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size = 0.3, random_state = 100)

###create decision tree classifier object
DT = DecisionTreeClassifier(criterion="gini", max_depth=4)
##fit decision tree model with training data
DT.fit(X_train, y_train)
##test data prediction
DT_expost_preds = DT.predict(X_test)

print(X_test.head(1))
DT_expost_preds[0]

def status(flag):
    if flag == 1:
        return "malicious"
    else:
        return "benign"

# X_predict = ['yahoo.fr','www.radsport-voggel.de/wp-admin/includes/log.exe','hello.ru', 'https://best-bonus.life/?u=pqhk60a&o=3a6gkf9']
url = input("Enter the Url : ")
df1 = pd.DataFrame({'url': [url]})
df1 = operation(df1)
df1.drop(columns=['url'],inplace=True)
result = DT.predict(df1)

print()
print("{} with the result as '{}'".format(url, status(result)))

