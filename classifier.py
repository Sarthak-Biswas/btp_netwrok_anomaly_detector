import pandas as pd
import seaborn as sns
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import os
import joblib

clf = joblib.load('model.joblib')
print(clf.predict([[113, 0.0, 1, 0.0, 0, 0.0, 64, 0.0, 0.0]]))