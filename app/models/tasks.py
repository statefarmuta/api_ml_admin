import numpy as np
import uuid
import tensorflow as tf
from tensorflow import keras
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib import rc
from sklearn.model_selection import train_test_split
from pandas.plotting import register_matplotlib_converters
from sklearn.preprocessing import RobustScaler
import os
import tempfile
import datetime
from app.common.database import Database
from sklearn.metrics import mean_squared_error

print("Import done")

register_matplotlib_converters()
sns.set(style='whitegrid', palette='muted', font_scale=1.5)

RANDOM_SEED = 42

np.random.seed(RANDOM_SEED)
tf.random.set_seed(RANDOM_SEED)

class DLModel:
    # the main variable in user model
    def __init__(self, project_id, csv_path, model_id, metric=None, prediction_img=None, model_path=None):
        self.project_id = int(project_id)
        self.model_id = model_id
        self.csv_path = csv_path
        self.metric = {} if metric is None else metric
        self.prediction_img = {} if prediction_img is None else prediction_img
        self.model_path = "" if model_path is None else model_path
        self.date = str(datetime.datetime.utcnow())
    

    @staticmethod
    def get_numerical(dataframe):
        categorical_variables = []
        threshold=10
        for c in dataframe:
            if len(np.unique(dataframe[c])) <= threshold:
                categorical_variables.append(c)

        values = []
        for col in dataframe:
            if col in categorical_variables:
                continue
            #get dtype for column
            dt = dataframe[col].dtype 
            #check if it is a number
            if dt == int or dt == float:
                values.append(col)
        values.remove('cnt')
        return values


    @staticmethod
    def initialize_database():
        Database.initialize()


    @staticmethod
    def smape(A, F):
        return 100/len(A) * np.sum(2 * np.abs(F - A) / (np.abs(A) + np.abs(F)))

    @classmethod
    def create_dataset(cls, X, y, time_steps=1):
        Xs, ys = [], []
        for i in range(len(X) - time_steps):
            v = X.iloc[i:(i + time_steps)].values
            Xs.append(v)        
            ys.append(y.iloc[i + time_steps])
        return np.array(Xs), np.array(ys)


    @classmethod
    def train_model(cls, csv_path, project_id, upload_dir):
        model_id = int(str(uuid.uuid4().int)[:6])
        df = pd.read_csv(
            upload_dir+"dataset/"+csv_path, 
            parse_dates=['timestamp'], 
            index_col="timestamp"
        )

        f_columns = DLModel.get_numerical(df)
        print(f_columns)
        df['hour'] = df.index.hour
        df['day_of_month'] = df.index.day
        df['day_of_week'] = df.index.dayofweek
        df['month'] = df.index.month

        train_size = int(len(df) * 0.9)
        test_size = len(df) - train_size
        train, test = df.iloc[0:train_size], df.iloc[train_size:len(df)]
        print(len(train), len(test))

        f_transformer = RobustScaler()
        cnt_transformer = RobustScaler()

        f_transformer = f_transformer.fit(train[f_columns].to_numpy())
        cnt_transformer = cnt_transformer.fit(train[['cnt']])

        train.loc[:, f_columns] = f_transformer.transform(train[f_columns].to_numpy())
        train['cnt'] = cnt_transformer.transform(train[['cnt']])

        test.loc[:, f_columns] = f_transformer.transform(test[f_columns].to_numpy())
        test['cnt'] = cnt_transformer.transform(test[['cnt']])

        time_steps = 10

        print("Data Preprocessing Done")
        # reshape to [samples, time_steps, n_features]

        X_train, y_train = cls.create_dataset(train, train.cnt, time_steps)
        X_test, y_test = cls.create_dataset(test, test.cnt, time_steps)

        print(X_train.shape, y_train.shape)

        print("Data spliting done")

        model = keras.Sequential()
        model.add(
        keras.layers.Bidirectional(
            keras.layers.LSTM(
            units=128, 
            input_shape=(X_train.shape[1], X_train.shape[2])
            )
            )
        )
        model.add(keras.layers.Dropout(rate=0.2))
        model.add(keras.layers.Dense(units=1))
        model.compile(loss='mean_squared_error', optimizer='adam')

        print("Traning")
        history = model.fit(
            X_train, y_train, 
            epochs=30, 
            batch_size=32, 
            validation_split=0.1,
            shuffle=False
        )

        print("Predicting")

        y_pred = model.predict(X_test)
        y_train_inv = cnt_transformer.inverse_transform(y_train.reshape(1, -1))
        y_test_inv = cnt_transformer.inverse_transform(y_test.reshape(1, -1))
        y_pred_inv = cnt_transformer.inverse_transform(y_pred)

        y_train_inv = cnt_transformer.inverse_transform(y_train.reshape(1, -1))
        y_test_inv = cnt_transformer.inverse_transform(y_test.reshape(1, -1))
        y_pred_inv = cnt_transformer.inverse_transform(y_pred)

        plt.plot(np.arange(0, len(y_train)), y_train_inv.flatten(), 'g', label="history")
        plt.plot(np.arange(len(y_train), len(y_train) + len(y_test)), y_test_inv.flatten(), marker='.', label="true")
        plt.plot(np.arange(len(y_train), len(y_train) + len(y_test)), y_pred_inv.flatten(), 'r', label="prediction")
        plt.ylabel('Bike Count')
        plt.xlabel('Time Step')
        plt.legend()
        model_pred_with_train = str(project_id)+"_"+str(model_id)+"_with_train.png"
        plt.savefig(upload_dir+"images/"+model_pred_with_train)
        plt.clf()
        plt.close()


        plt.plot(y_test_inv.flatten(), marker='.', label="true")
        plt.plot(y_pred_inv.flatten(), 'r', label="prediction")
        plt.ylabel('Bike Count')
        plt.xlabel('Time Step')
        plt.legend()
        model_pred_test = str(project_id)+"_"+str(model_id)+"_test.png"
        plt.savefig(upload_dir+"images/"+model_pred_test)
        plt.clf()
        plt.close()

        rmse = mean_squared_error(np.reshape(y_test_inv, (max(y_test_inv.shape[0], y_test_inv.shape[1]) )), np.reshape(y_pred_inv, (max(y_pred_inv.shape[0], y_pred_inv.shape[1]) )), squared=False)
        
        smape = DLModel.smape( np.reshape(y_test_inv, (max(y_test_inv.shape[0], y_test_inv.shape[1]) )), np.reshape(y_pred_inv, (max(y_pred_inv.shape[0], y_pred_inv.shape[1]) )) )

        nrmse = rmse/(max(np.reshape(y_test_inv, (max(y_test_inv.shape[0], y_test_inv.shape[1]) ))) - min(np.reshape(y_test_inv, (max(y_test_inv.shape[0], y_test_inv.shape[1]) )))  )

        # Fetch the Keras session and save the model
        # The signature definition is defined by the input and output tensors,
        # and stored with the default serving key
        print("Saving")
        export_path = os.path.join(upload_dir+"models/", str(model_id))
        print('export_path = {}\n'.format(export_path))

        tf.keras.models.save_model(
            model,
            export_path,
            overwrite=True,
            include_optimizer=True,
            save_format=None,
            signatures=None,
            options=None
        )

        print('\nSaved model')
        DLModel.initialize_database()
        new_model = cls(project_id, csv_path, model_id, metric={"rmse":rmse, "smape":smape, "nrmse":nrmse}, prediction_img={"model_pred_test":model_pred_test, "model_pred_with_train":model_pred_with_train}, model_path=export_path)
        new_model.save_to_mongo()

        Database.update_one(collection='projects', query=[{'project_id':int(project_id)}, { "$set": { "model_available": True } } ])

    def json(self):
        return {
            "model_id" : self.model_id,
            "project_id": self.project_id,
            "csv_path": self.csv_path,
            "metric": self.metric,
            "prediction_img": self.prediction_img,
            "model_path": self.model_path,
            "date": self.date
        }


    def save_to_mongo(self):
        print(self.json())
        Database.insert(collection='models', data=self.json())
