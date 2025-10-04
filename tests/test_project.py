"""
Basic tests for Network IDS project
Tests deployment readiness and file structure
"""
import os
import sys
import pytest

# Test 1: Verify model files exist
def test_model_files_exist():
    """Test that all required model files are present"""
    model_files = [
        "models/NetworkIDS_AWS_MultiDataset_v1_lightweight.pkl",
        "models/scaler.pkl",
        "models/label_encoder.pkl"
    ]
    for model_file in model_files:
        assert os.path.exists(model_file), f"Missing model file: {model_file}"
    print("✅ All model files found")

# Test 2: Verify application files exist
def test_app_files_exist():
    """Test that main application files are present"""
    required_files = [
        "app/realtime_detector1.py",
        "Dockerfile",
        "docker-compose.yml",
        "requirements.txt"
    ]
    for file in required_files:
        assert os.path.exists(file), f"Missing file: {file}"
    print("✅ All application files found")

# Test 3: Verify Kubernetes manifests exist
def test_kubernetes_files_exist():
    """Test that Kubernetes deployment files are present"""
    k8s_files = [
        "k8s/deployment.yaml",
        "k8s/service.yaml"
    ]
    for k8s_file in k8s_files:
        assert os.path.exists(k8s_file), f"Missing K8s file: {k8s_file}"
    print("✅ All Kubernetes files found")

# Test 4: Verify CI/CD workflow exists
def test_cicd_workflow_exists():
    """Test that GitHub Actions CI/CD workflow is configured"""
    workflow_file = ".github/workflows/ci-cd.yml"
    assert os.path.exists(workflow_file), f"Missing CI/CD workflow: {workflow_file}"
    print("✅ CI/CD workflow found")

# Test 5: Test Python imports
def test_python_imports():
    """Test that required Python packages can be imported"""
    try:
        import streamlit
        import pandas
        import numpy
        import sklearn
        import joblib
        print("✅ All Python packages importable")
    except ImportError as e:
        pytest.fail(f"Failed to import required package: {e}")

# Test 6: Verify Docker can be used
def test_docker_available():
    """Test that Docker is available on the system"""
    result = os.system("docker --version > nul 2>&1")
    assert result == 0, "Docker is not available or not installed"
    print("✅ Docker is available")

# Test 7: Test requirements.txt is valid
def test_requirements_file():
    """Test that requirements.txt contains expected packages"""
    with open("requirements.txt", "r") as f:
        content = f.read().lower()
        required_packages = ["streamlit", "pandas", "numpy", "scikit-learn"]
        for package in required_packages:
            assert package in content, f"Package '{package}' not in requirements.txt"
    print("✅ requirements.txt is valid")
