# Create dataset for ML.

from random import seed
from random import randint
from random import uniform
import csv

# seed random number generator.
seed(1)

''' 
    define 5 classifications:
        Healthy (H1): 
        "Could do better" healthy (H2):   
        "Slacker" Unhealthy (H3):
        "Does not care" Unhealthy (H4):
        "Critical Condition" Unhealthy (H5):
'''

def randomize(data_writer, Age, calories, caloriesMets, steps, distance, floors, elevation, heartRate, SleepScore, label):
    for i in range(100):
        A = randint(Age-5,Age+5);
        C1 = uniform(calories-1000,calories+1000)
        if(C1 < 0):
            C1 = 0
        C2 = uniform(caloriesMets-20,caloriesMets+20)
        if(C2 < 0):
            C2 = 0
        S = randint(steps-2000,steps+2000)
        if(S < 0):
            S = 0
        D = uniform(distance-5,distance+5)
        if(D < 0):
            D = 0
        F = randint(floors-7,floors+7)
        if(F < 0):
            F = 0
        E = randint(elevation-5,elevation+5)
        if(E < 0):
            E = 0
        H = randint(heartRate-10,heartRate+10)
        SS = randint(SleepScore-20,SleepScore+20)
        if(SS < 0):
            SS = 0
        if(SS > 100):
            SS = 100
        L = label
        
        data_writer.writerow([A,C1,C2,S,D,F,E,H,SS,L])
    
    

# create filename.
filename = 'data_train.csv'
with open(filename, mode='w', newline='') as file:
    data_writer = csv.writer(file, delimiter=',')
    
    # write header to file.
    data_writer.writerow(['Age','Calories', 'CaloriesMets', 'Steps', 'Distance', 'Floors', 'Elevation', 'HeartRate', 'SleepScore', 'HealthStatus'])
        
    H1_Label = 1
    H2_Label = 2
    H3_Label = 3
    H4_Label = 4
    H5_Label = 5
    
    # Age range 20-30 and is healthy
    Age = 25
    H1_calories = 2600
    H1_caloriesMets = 13.5
    H1_Steps = 10000
    H1_Distance = 8
    H1_Floors = 7
    H1_Elevation = 7
    H1_HeartRate = 70
    H1_SleepScore = 95 
    randomize(data_writer, Age, H1_calories, H1_caloriesMets, H1_Steps, H1_Distance, H1_Floors, H1_Elevation, H1_HeartRate, H1_SleepScore, H1_Label)
    
    # Age range 30-40 and is healthy
    Age = 35
    H1_calories = 2600
    H1_caloriesMets = 11.4
    H1_Steps = 9500
    H1_Distance = 7.5
    H1_Floors = 7
    H1_Elevation = 7
    H1_HeartRate = 70
    H1_SleepScore = 95
    randomize(data_writer, Age, H1_calories, H1_caloriesMets, H1_Steps, H1_Distance, H1_Floors, H1_Elevation, H1_HeartRate, H1_SleepScore, H1_Label)
    
    # Age range 40-50 and is healthy
    Age = 45
    H1_calories = 2400
    H1_caloriesMets = 10.3
    H1_Steps = 9000
    H1_Distance = 7
    H1_Floors = 6
    H1_Elevation = 6
    H1_HeartRate = 70
    H1_SleepScore = 95
    randomize(data_writer, Age, H1_calories, H1_caloriesMets, H1_Steps, H1_Distance, H1_Floors, H1_Elevation, H1_HeartRate, H1_SleepScore, H1_Label)
    
    # Age range 20-30 and is "Could do better" healthy
    Age = 25
    H2_calories = 2000
    H2_caloriesMets = 11.5
    H2_Steps = 8000
    H2_Distance = 6
    H2_Floors = 5
    H2_Elevation = 5
    H2_HeartRate = 75
    H2_SleepScore = 90 
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H2_Label)
    
    # Age range 30-40 and is "Could do better" healthy
    Age = 35
    H2_calories = 2000
    H2_caloriesMets = 10.4
    H2_Steps = 8000
    H2_Distance = 5.5
    H2_Floors = 5
    H2_Elevation = 5
    H2_HeartRate = 75
    H2_SleepScore = 90
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H2_Label)
    
    # Age range 40-50 and is "Could do better" healthy
    Age = 45
    H2_calories = 1900
    H2_caloriesMets = 9.3
    H2_Steps = 7500
    H2_Distance = 5.5
    H2_Floors = 5
    H2_Elevation = 5
    H2_HeartRate = 75
    H2_SleepScore = 90
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H2_Label)
    
    # Age range 20-30 and is "Slacker" healthy
    Age = 25
    H2_calories = 1800
    H2_caloriesMets = 9.8
    H2_Steps = 6000
    H2_Distance = 5
    H2_Floors = 4
    H2_Elevation = 4
    H2_HeartRate = 80
    H2_SleepScore = 82 
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H3_Label)
    
    # Age range 30-40 and is "Slacker" healthy
    Age = 35
    H2_calories = 1500
    H2_caloriesMets = 9.0
    H2_Steps = 5500
    H2_Distance = 5
    H2_Floors = 4
    H2_Elevation = 4
    H2_HeartRate = 80
    H2_SleepScore = 82
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H3_Label)
    
    # Age range 40-50 and is "Slacker" healthy
    Age = 45
    H2_calories = 1500
    H2_caloriesMets = 8.7
    H2_Steps = 5000
    H2_Distance = 4.5
    H2_Floors = 4
    H2_Elevation = 4
    H2_HeartRate = 80
    H2_SleepScore = 82
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H3_Label)
    
    # Age range 20-30 and is "Does not care" healthy
    Age = 25
    H2_calories = 1400
    H2_caloriesMets = 8.4
    H2_Steps = 4500
    H2_Distance = 4
    H2_Floors = 3
    H2_Elevation = 3
    H2_HeartRate = 80
    H2_SleepScore = 70 
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H4_Label)
    
    # Age range 30-40 and is "Does not care" healthy
    Age = 35
    H2_calories = 1300
    H2_caloriesMets = 7.6
    H2_Steps = 4000
    H2_Distance = 4
    H2_Floors = 3
    H2_Elevation = 3
    H2_HeartRate = 80
    H2_SleepScore = 70
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H4_Label)
    
    # Age range 40-50 and is "Does not care" healthy
    Age = 45
    H2_calories = 1100
    H2_caloriesMets = 6.5
    H2_Steps = 4000
    H2_Distance = 4
    H2_Floors = 3
    H2_Elevation = 3
    H2_HeartRate = 80
    H2_SleepScore = 70
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H4_Label)
    
    # Age range 20-30 and is "Critical Condition" healthy
    Age = 25
    H2_calories = 1000
    H2_caloriesMets = 7.4
    H2_Steps = 3000
    H2_Distance = 3
    H2_Floors = 2
    H2_Elevation = 2
    H2_HeartRate = 80
    H2_SleepScore = 65 
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H5_Label)
    
    # Age range 30-40 and is "Critical Condition" healthy
    Age = 35
    H2_calories = 1000
    H2_caloriesMets = 6.0
    H2_Steps = 3000
    H2_Distance = 2
    H2_Floors = 1
    H2_Elevation = 1
    H2_HeartRate = 80
    H2_SleepScore = 65
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H5_Label)
    
    # Age range 40-50 and is "Critical Condition" healthy
    Age = 45
    H2_calories = 900
    H2_caloriesMets = 5.5
    H2_Steps = 3500
    H2_Distance = 2
    H2_Floors = 1
    H2_Elevation = 1
    H2_HeartRate = 80
    H2_SleepScore = 65
    randomize(data_writer, Age, H2_calories, H2_caloriesMets, H2_Steps, H2_Distance, H2_Floors, H2_Elevation, H2_HeartRate, H2_SleepScore, H5_Label)
    