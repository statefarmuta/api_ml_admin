from sklearn.neural_network import MLPClassifier
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
model = MLPClassifier(hidden_layer_sizes=(20, 10), max_iter=5000, alpha=0.0001, solver='lbfgs', verbose=10, random_state=1)
model.fit(X_train, y_train)

# compute testing results
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

# print results for debugging
print("TRAINING SAMPLES: " + str(len(X_train)))
print("TESTING SAMPLES: " + str(len(X_test)))
print("TESTING ACCURACY: " + str(accuracy))

#test_sample = [31,2177,11.3,3648,2.7,3,9,80,96]
test_sample = [22,1100,11.3,150,1.5,2,2,75,72]
x = np.array([test_sample])

# compute the classification result
result = int(model.predict(scaler.transform(x)))
print("Single test sample result: " + str(result))

