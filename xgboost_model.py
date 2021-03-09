from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import pandas as pd
import numpy as np

# load the input train/test datasets from CSV
train_data = pd.read_csv("data_train.csv")

# get the input parameters of the samples
X_train = train_data.drop(['HealthStatus'], axis=1)

# get the classification labels of the samples
y_train = train_data['HealthStatus']


#split a single data set into test / training sets
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X_train, y_train, test_size= 0.25, shuffle=True, random_state=1)

# scale the training and testing data
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
scaler.fit(X_train)
X_train = scaler.transform(X_train)
X_test = scaler.transform(X_test)


# perform the training
model = XGBClassifier()
model.fit(X_train, y_train)

# compute testing results
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

# print results for debugging
print("TRAINING SAMPLES: " + str(len(X_train)))
print("TESTING SAMPLES: " + str(len(X_test)))
print("TESTING ACCURACY: " + str(accuracy))


# find how off the results are.
r = X_test.shape[0]    # rows
match = 0
diff_1 = 0
diff_2 = 0
diff_3 = 0
diff_4 = 0

correct_outcomes = np.array(y_test)
transpose = correct_outcomes.T

for i in range(r):
    x = np.array([scaler.inverse_transform(X_test[i])])
    result = int(model.predict(scaler.transform(x)))
    if result == transpose[i]:
        match = match + 1
    if abs(result-transpose[i]) == 1:
        diff_1 = diff_1 + 1
    if abs(result-transpose[i]) == 2:
        diff_2 = diff_2 + 1
    if abs(result-transpose[i]) == 3:
        diff_3 = diff_3 + 1
    if abs(result-transpose[i]) == 4:
        diff_4 = diff_4 + 1
        
print("% of Exact Matches: " + str(match/r*100))
print("% of differed by 1: " + str(diff_1/r*100))
print("% of differed by 2: " + str(diff_2/r*100))
print("% of differed by 3: " + str(diff_3/r*100))
print("% of differed by 4: " + str(diff_4/r*100))


'''
test_sample = [31,2177,11.3,3648,2.7,3,9,80,96]
x = np.array([test_sample])

# compute the classification result
result = int(model.predict(scaler.transform(x)))
print("Single test sample result: " + str(result))

test_sample = [22,1100,11.3,150,1.5,2,2,75,72]
x = np.array([test_sample])

# compute the classification result
result = int(model.predict(scaler.transform(x)))
print("Single test sample result: " + str(result))
'''