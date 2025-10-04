text
# Network Intrusion Detection System (IDS)

Real-time ML-based Network Security System with DevOps Pipeline

[![CI/CD Pipeline](https://github.com/KarNa1312/NetworkIDS_Project/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/KarNa1312/NetworkIDS_Project/actions)
[![Docker Hub](https://img.shields.io/docker/pulls/karna1312/network-ids-app)](https://hub.docker.com/r/karna1312/network-ids-app)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Local Development](#local-development)
- [Testing](#testing)
- [CI/CD Pipeline](#cicd-pipeline)
- [Project Structure](#project-structure)
- [Performance Metrics](#performance-metrics)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Overview

A containerized, production-ready Network Intrusion Detection System that uses machine learning to detect cyber attacks in real-time. The system employs Flow Transformer and Topological Data Analysis techniques to identify various attack patterns including DDoS, Phishing, Ransomware, Brute Force, and more.

This project demonstrates a complete DevOps pipeline including automated CI/CD with GitHub Actions, Docker containerization, Kubernetes orchestration, automated testing, and container registry deployment.

The system is trained on the CICIDS2018 dataset with 29 network flow features, achieving 98.5% accuracy in detecting multiple attack types.

## Features

### Machine Learning Capabilities

- Multi-class classification detecting 10+ attack types
- Advanced ML techniques using Flow Transformer and Topological Data Analysis ensemble
- Real-time prediction with sub-second inference time
- High accuracy of 98.5% on test dataset
- Lightweight model optimized for production deployment

### DevOps and Deployment

- Docker containerization for portable deployment across platforms
- Kubernetes orchestration with auto-scaling and self-healing capabilities
- Automated CI/CD pipeline with GitHub Actions
- Zero-downtime rolling updates
- Infrastructure as Code with version-controlled deployment configurations

### Application Features

- Interactive web dashboard built with Streamlit
- Real-time network attack monitoring
- Persistent logging with SQLite database for audit trails
- Visual alerts with color-coded threat levels
- Historical analysis and trend visualization

## Technologies Used

**Machine Learning**: Scikit-learn, XGBoost, Joblib

**Web Framework**: Streamlit

**Containerization**: Docker, Docker Compose

**Orchestration**: Kubernetes, Minikube

**CI/CD**: GitHub Actions

**Version Control**: Git, Git LFS, GitHub

**Database**: SQLite

**Programming Language**: Python 3.10

**Container Registry**: Docker Hub

**Testing**: pytest

## Quick Start

### Using Docker (Fastest Method)

docker pull karna1312/network-ids-app:latest
docker run -p 8501:8501 karna1312/network-ids-app:latest

text

Open your browser and navigate to http://localhost:8501

## Docker Deployment

### Option 1: Basic Docker Run

docker pull karna1312/network-ids-app:latest
docker run -p 8501:8501 karna1312/network-ids-app:latest

text

### Option 2: Docker with Volume Mounts

Clone the repository first:

git clone https://github.com/KarNa1312/NetworkIDS_Project.git
cd NetworkIDS_Project

text

On Linux or macOS:

docker run --rm -p 8501:8501
-v $(pwd)/models:/app/models
-v $(pwd)/data:/app/data
karna1312/network-ids-app:latest

text

On Windows PowerShell:

docker run --rm -p 8501:8501 -v ${PWD}/models:/app/models
-v ${PWD}/data:/app/data `
karna1312/network-ids-app:latest

text

On Windows Command Prompt:

docker run --rm -p 8501:8501 ^
-v "%cd%\models:/app/models" ^
-v "%cd%\data:/app/data" ^
karna1312/network-ids-app:latest

text

### Option 3: Docker Compose

git clone https://github.com/KarNa1312/NetworkIDS_Project.git
cd NetworkIDS_Project
docker compose up

text

To stop the application:

docker compose down

text

## Kubernetes Deployment

### Prerequisites

- Minikube or Kubernetes cluster installed
- kubectl CLI tool installed

### Deploy to Kubernetes

Start Minikube for local testing:

minikube start

text

Apply Kubernetes manifests:

kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

text

Verify the deployment:

kubectl get deployments
kubectl get pods
kubectl get services

text

Access the application:

minikube service network-ids-service --url

text

### Kubernetes Operations

**Scale the deployment:**

kubectl scale deployment network-ids-deployment --replicas=5
kubectl get pods -w

text

**Test self-healing:**

kubectl delete pod <pod-name>
kubectl get pods -w

text

**Rolling updates:**

kubectl set image deployment/network-ids-deployment
network-ids-container=karna1312/network-ids-app:latest
kubectl rollout status deployment/network-ids-deployment

text

**View logs:**

kubectl logs -l app=network-ids --tail=50
kubectl logs <pod-name> --follow

text

**Port forwarding:**

kubectl port-forward service/network-ids-service 8501:8501

text

## Local Development

### Prerequisites

- Python 3.10 or higher
- Docker Desktop (optional)
- Git

### Setup Instructions

Clone the repository:

git clone https://github.com/KarNa1312/NetworkIDS_Project.git
cd NetworkIDS_Project

text

Create and activate virtual environment:

On Windows:

python -m venv venv
venv\Scripts\activate

text

On Linux or macOS:

python -m venv venv
source venv/bin/activate

text

Install dependencies:

pip install --upgrade pip
pip install -r requirements.txt

text

Run the application:

streamlit run app/realtime_detector1.py

text

The application will open at http://localhost:8501

## Testing

### Run Tests

Install test dependencies:

pip install pytest

text

Run all tests:

pytest tests/ -v

text

Run with coverage:

pip install pytest-cov
pytest tests/ --cov=app --cov-report=html

text

Run specific test file:

pytest tests/test_project.py -v

text

### Test Coverage

The test suite validates:

- Model files exist and are accessible
- Application files are present
- Kubernetes manifests are configured correctly
- CI/CD workflow exists
- Python packages can be imported
- Docker is available
- Requirements file is valid

## CI/CD Pipeline

The project uses GitHub Actions for automated continuous integration and deployment.

### Pipeline Stages

1. Checkout code from repository
2. Set up Python 3.10 environment
3. Install dependencies from requirements.txt
4. Run automated tests with pytest
5. Build Docker image
6. Push image to Docker Hub registry

### Triggering the Pipeline

The pipeline automatically runs on every push to the main branch:

git add .
git commit -m "Your commit message"
git push origin main

text

Manual trigger from GitHub Actions tab is also available.

### Viewing Pipeline Status

Visit the Actions tab in your GitHub repository to view pipeline execution status and logs.

## Project Structure

NetworkIDS_Project/
├── .github/
│ └── workflows/
│ └── ci-cd.yml
├── app/
│ └── realtime_detector1.py
├── models/
│ ├── NetworkIDS_AWS_MultiDataset_v1_lightweight.pkl
│ ├── scaler.pkl
│ └── label_encoder.pkl
├── data/
│ └── security_incidents.db
├── k8s/
│ ├── deployment.yaml
│ └── service.yaml
├── tests/
│ └── test_project.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .dockerignore
├── .gitignore
└── README.md

text

## Performance Metrics

**Model Accuracy**: 98.5%

**Inference Time**: Less than 100ms per prediction

**Container Image Size**: Approximately 2.5GB

**Container Startup Time**: Approximately 30 seconds

**Memory Usage**: Approximately 1.5GB per pod

**CPU Usage (idle)**: Approximately 5%

**Supported Attack Types**: 10+ categories

## Troubleshooting

### Port Already in Use

Find the process using the port:

netstat -ano | findstr :8501

text

Kill the process on Windows:

taskkill /PID <PID> /F

text

Or use a different port:

docker run -p 8502:8501 karna1312/network-ids-app:latest

text

### Models Not Loading

Ensure volume mounts are correct:

docker run -v $(pwd)/models:/app/models karna1312/network-ids-app:latest

text

Check if models exist locally:

ls models/

text

### Kubernetes Pod Issues

Check pod logs:

kubectl logs <pod-name>

text

Describe pod for detailed information:

kubectl describe pod <pod-name>

text

Verify image exists:

docker pull karna1312/network-ids-app:latest

text

### GitHub Actions Failures

- Verify Docker Hub credentials are set in GitHub repository secrets
- Check YAML syntax for workflow file
- Review detailed logs in the GitHub Actions tab

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/YourFeature`
3. Commit your changes: `git commit -m 'Add YourFeature'`
4. Push to the branch: `git push origin feature/YourFeature`
5. Open a Pull Request

### Guidelines

- Follow PEP 8 style guide for Python code
- Add tests for new features
- Update documentation for any API changes
- Ensure CI/CD pipeline passes before submitting

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Academic Context

This project was developed as part of the DevOps course at K.E. Society's Rajarambapu Institute of Technology.

**Course**: DevOps (CS447)

**Department**: Computer Science and Engineering

**Academic Year**: 2024-2025

**Project Type**: Mini-Project ISE Evaluation

### Learning Objectives Achieved

- Applied DevOps practices including automation, CI/CD, and containerization
- Implemented version control with Git and GitHub
- Deployed applications using container orchestration with Kubernetes
- Built end-to-end software delivery pipeline
- Integrated testing and monitoring

## Acknowledgments

- CICIDS2018 Dataset provided by the Canadian Institute for Cybersecurity, University of New Brunswick
- Streamlit team for the excellent web framework
- Docker and Kubernetes communities for comprehensive documentation
- Open source ML libraries including scikit-learn, XGBoost, and pandas

## Contact

**GitHub Repository**: https://github.com/KarNa1312/NetworkIDS_Project

**Docker Hub**: https://hub.docker.com/r/karna1312/network-ids-app

**GitHub Profile**: https://github.com/KarNa1312

**Report Issues**: https://github.com/KarNa1312/NetworkIDS_Project/issues

**Pull Requests**: https://github.com/KarNa1312/NetworkIDS_Project/pulls

## Documentation

- Docker Documentation: https://docs.docker.com/
- Kubernetes Documentation: https://kubernetes.io/docs/
- Streamlit Documentation: https://docs.streamlit.io/
- GitHub Actions Documentation: https://docs.github.com/en/actions
- CICIDS2018 Dataset: https://www.unb.ca/cic/datasets/ids-2018.html

Last Updated: October 2025