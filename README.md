# Network Intrusion Detection System (Capstone Project)

## Steps to Run
1. Install requirements: `pip install -r requirements.txt`
2. Run app: `streamlit run app/realtime_detector1.py`
3. Open browser at: http://localhost:8501

# Network Intrusion Detection System

Real-time ML-based Network IDS using Flow Transformer and TDA.

## Features
- Real-time attack detection
- Multiple attack types (DDoS, Phishing, Ransomware, etc.)
- SQLite logging for persistence
- Streamlit dashboard

## Run with Docker

### Pull from Docker Hub
```
docker pull karna1312/network-ids-app:latest
```

### Run the app
```
docker run -p 8501:8501 karna1312/network-ids-app:latest
```

Open http://localhost:8501 in your browser.

### Run with custom models (optional)
```
docker run -p 8501:8501 -v /path/to/models:/app/models karna1312/network-ids-app:latest
```

## Local Development

### Install dependencies
```
pip install -r requirements.txt
```

### Run locally
```
streamlit run app/realtime_detector1.py
```

## Repository Structure
```
NetworkIDS_Project/
├── app/                    # Streamlit application
├── models/                 # ML models (.pkl files)
├── data/                   # Database storage
├── notebooks/              # Jupyter notebooks
├── Dockerfile              # Docker configuration
├── docker-compose.yml      # Docker Compose setup
└── requirements.txt        # Python dependencies
```

## Technologies Used
- Python 3.10
- Streamlit
- Scikit-learn
- XGBoost
- Docker
- SQLite
```
