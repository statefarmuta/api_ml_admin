'''
    TODO::  Data Type Identification (Discrete, Continuous, Categorical) -> DICT
            Handling Missing values:
                Categorical/Textual data -> Cardinality increase
                Discrete/Numericals data -> Median flooding, KKN* (Append column denoting the imputer rows)
            Handling Categorical Varibles:
                One hot encoding
            Text Data:
                TIDF sparse matrix
            Discrete Data:
                Normalize check distribution [-1, 1] or [1, 1]
'''

def get_data_types(dataFrame)->dict:
    
    pass


def categorical_missing_handler(dataFrame, columns:list):
    pass


def discrete_missing_handler(dataFrame, columns:list):
    pass


def categorical_handler(dataFrame, columns:list):
    pass


def discrete_handler(dataFrame, columns:list):
    pass


def text_handler(dataFrame, columns:list):
    pass


def impute_dataframe(dataFrame, data_types)->list:
    pass

