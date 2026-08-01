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

app = Flask(__name__, static_folder='static', static_url_path='/static')

# Load model if present
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
            features = obj.getFeaturesList()
            x = np.array(features).reshape(1, 30)
            
            # Calculate dynamic heuristic score based on 30 indicators
            safe_indicators = sum(1 for f in features if f == 1)
            heuristic_score = round((safe_indicators / 30.0) * 100, 1)

            if gbc is not None:
                y_pred = gbc.predict(x)[0]
                if hasattr(gbc, "predict_proba"):
                    proba = gbc.predict_proba(x)[0]
                    score = round(float(max(proba)) * 100, 1)
                else:
                    score = heuristic_score
            else:
                y_pred = 1 if heuristic_score >= 60.0 else -1
                score = heuristic_score

            name = convertion(url, int(y_pred), score)
        except Exception as e:
            name = [url, "Error analyzing URL", "Try again", False, 50.0]
        return render_template('index.html', name=name)
    return render_template('index.html')

@app.route('/usecases', methods=['GET', 'POST'])
def usecases():
    return render_template('usecases.html')

if __name__ == '__main__':
    app.run(debug=True)
