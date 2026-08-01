import os
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, render_template
from sklearn import metrics
import warnings
import pickle
from convert import convertion
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

app = Flask(__name__)

# Load model if present, otherwise set to None
gbc = None
if os.path.exists('newmodel.pkl'):
    try:
        with open('newmodel.pkl', 'rb') as file:
            gbc = pickle.load(file)
    except Exception as e:
        print("Error loading model:", e)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/result', methods=['POST', 'GET'])
def predict():
    if request.method == 'POST':
        url = request.form['name']
        try:
            obj = FeatureExtraction(url)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)
            if gbc is not None:
                y_pred = gbc.predict(x)[0]
            else:
                y_pred = 1 # Fallback prediction if model missing
            name = convertion(url, int(y_pred))
        except Exception as e:
            name = [url, "Error analyzing URL", "Try again", False]
        return render_template('index.html', name=name)
    return render_template('index.html')

@app.route('/usecases', methods=['GET', 'POST'])
def usecases():
    return render_template('usecases.html')

if __name__ == '__main__':
    app.run(debug=True)
