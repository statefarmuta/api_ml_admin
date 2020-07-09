import pandas as pd
import numpy as np

class Analysis(object):
    def __init__(self, dataset_uri):
        self.dataset_uri = dataset_uri

    @staticmethod
    def get_data_head(dataset_uri):
        df = pd.read_csv(dataset_uri)
        df = df.head()
        html = [df.to_html()]
        titles = df.columns.values
        return [html, titles]

    @staticmethod
    def fillna(dataframe):
        for col in dataframe:
            #get dtype for column
            dt = dataframe[col].dtype 
            #check if it is a number
            if dt == int or dt == float:
                dataframe[col].fillna(0, inplace=True)
            else:
                dataframe[col].fillna("None", inplace=True)
        return dataframe


    @staticmethod
    def get_numerical(dataframe):
        values = {}
        for col in dataframe:
            #get dtype for column
            dt = dataframe[col].dtype 
            #check if it is a number
            if dt == int or dt == float:
                values[col] = dataframe[col].values[:45].tolist()

        return values


    @staticmethod
    def get_coloums_stat(dataset_uri):
        df = pd.read_csv(dataset_uri)
        df = Analysis.fillna(df)
        
        numerical_vals = Analysis.get_numerical(df)

        titles = df.columns.values
        stats_dict = df.describe().to_dict()
        stats_df_titles = df.describe().columns.values
        stats_table = {}

        column_type = 'numerical' 
        categorical_variables = []
        threshold=10
        for c in titles:
            if len(np.unique(df[c])) <= threshold:
                categorical_variables.append(c)

        for title in titles:

            if title in categorical_variables:
                column_type = 'categorical'
            else:
                column_type = None

            if title in stats_df_titles:
                stats_table[title] = {
                                        'type': column_type if column_type is not None else 'numerical', 
                                        'chart': 'chart' if column_type is not None else 'numerical',
                                        'mean':stats_dict[title]['mean'],
                                        'min':stats_dict[title]['min'],
                                        'max':stats_dict[title]['max'],
                                        'sum':df[title].sum(),
                                        'std_dev':stats_dict[title]['std']
                                     }
            else:
                stats_table[title] = { 'type': column_type if column_type is not None else 'string', 
                                        'chart': 'chart' if column_type is not None else 'numerical',
                                        'mean':'N/A',
                                        'min':'N/A',
                                        'max':'N/A',
                                        'sum':'N/A',
                                        'std_dev':'N/A'
                                     }
    
        return [stats_table,titles, numerical_vals]