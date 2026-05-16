# Mini SIEM – ML Threat Detection System

![Python](https://img.shields.io/badge/Python-3.10-blue)
![Flask](https://img.shields.io/badge/Flask-WebApp-black)
![Machine Learning](https://img.shields.io/badge/ML-RandomForest-green)
![Cybersecurity](https://img.shields.io/badge/Security-SIEM-red)

A Hybrid Cybersecurity Threat Detection System developed using Flask, SQLite, Rule-Based Detection, and Machine Learning (Random Forest).

This project simulates the core functionality of a SIEM (Security Information and Event Management) system by monitoring login activity, detecting suspicious behavior, generating alerts, and visualizing results through a dashboard.

---

# Project Overview

The system analyzes cybersecurity activity using:

- Rule-Based Threat Detection
- Machine Learning-Based Threat Detection
- Real-Time Log Monitoring
- File Upload Analysis
- Dashboard Visualization
- Secure Authentication
- Hybrid Risk Classification

The project combines traditional security rules with machine learning predictions to improve threat detection accuracy and provide intelligent cybersecurity monitoring.

---

# Key Features

## Authentication & Security
- Secure User Registration & Login
- Password Hashing using bcrypt
- Session-Based Authentication
- Multi-user Isolation
- Secure Credential Validation

---

## Threat Detection
- Rule-Based Detection Engine
- Random Forest Machine Learning Model
- Hybrid Threat Analysis
- Real-Time Risk Classification
- Suspicious Activity Detection

### Risk Levels
- LOW
- MEDIUM
- HIGH
- CRITICAL

---

## Monitoring & Analysis
- Manual Threat Analysis
- Log File Upload Detection
- Real-Time Log Monitoring
- Attack Pattern Analysis
- IP-Based Suspicious Activity Tracking

---

## Dashboard
- Alert Statistics
- Risk Distribution
- Threat Visualization
- Top Attacker IPs
- Real-Time Monitoring Interface

---

# Technologies Used

| Technology | Purpose |
|------------|---------|
| Python | Backend Development |
| Flask | Web Framework |
| SQLite | Database Management |
| HTML/CSS/JavaScript | Frontend Development |
| Random Forest | Machine Learning |
| bcrypt | Password Security |
| Joblib | ML Model Loading |
| Jinja2 | Template Rendering |

---

# Machine Learning Model

The project uses a pre-trained Random Forest Classifier for intelligent threat detection.

## ML Workflow

### Dataset
- Dataset Used: `cyber_activity_10000.csv`
- Approximate Records: 10,000 cybersecurity activity records

---

### Dataset Split
- 70% Training Data
- 30% Testing Data

---

### Machine Learning Model
- Algorithm: Random Forest Classifier
- Number of Decision Trees: 200
- Classification Type: Supervised Learning

---

### Model Training Process
1. Dataset preprocessing
2. Feature extraction
3. Train-test split
4. Random Forest model training
5. Accuracy evaluation
6. Model saved as `model.pkl`

---

### Runtime Prediction
The model predicts suspicious activity using:

```python
prediction = model.predict(features)
```

---

# Hybrid Detection Logic

The system combines Rule-Based Detection and Machine Learning Detection for improved accuracy.

---

## Rule-Based Detection

Example Rules:

- If login attempts > 20
- AND failed attempts > 10
- → HIGH RISK

- If failed attempts > 5
- → MEDIUM RISK

---

## Machine Learning Detection

The ML model predicts:
- Normal Activity
- Suspicious Activity

based on:
- Login Attempts
- Failed Attempts
- IP Behavior
- Login Patterns
- Time-Based Features

---

## Final Hybrid Decision

Rule-Based Result + ML Prediction → Final Risk Level

This hybrid approach improves:
- Detection Accuracy
- Stability
- Reliability
- Real-Time Performance

---

# Project Structure

```bash
mini-siem-ml-threat-detection/
│
├── app.py
├── model.pkl
├── cyber_activity_10000.csv
├── requirements.txt
├── README.md
├── Mini_SIEM_Project_Documentation.docx
│
├── detection/
│   ├── ml_detector.py
│   ├── rule_engine.py
│   ├── risk_scoring.py
│   └── log_parser.py
│
├── templates/
│   ├── dashboard.html
│   ├── login.html
│   ├── manual.html
│   ├── monitoring.html
│   ├── upload.html
│   └── home.html
│
├── logs/
│   └── sample.log
│
├── screenshots/
│
└── static/
```

---

# System Workflow

## Manual Threat Detection

1. User enters login activity details
2. System preprocesses input
3. Rule-based engine analyzes activity
4. ML model predicts suspicious behavior
5. Hybrid engine generates final risk level
6. Result stored in database
7. Dashboard updated

---

## File Upload Detection

1. User uploads log file
2. File parsed line-by-line
3. Features extracted from logs
4. Detection engine processes data
5. Threat alerts generated
6. Results displayed on dashboard

---

## Real-Time Monitoring

1. System continuously monitors logs
2. Detects new suspicious entries
3. Automatically processes activities
4. Generates alerts in real time

---

# Dashboard Features

The dashboard provides:

- Total Alert Statistics
- Risk Level Distribution
- Threat Visualization
- Real-Time Monitoring Data
- Top Suspicious IP Addresses
- Alert Management

---

# Database Features

The system stores:

- User Information
- Login Sessions
- Threat Alerts
- Detection Results
- Monitoring Logs

SQLite is used for lightweight and efficient database management.

---

# Security Features

- bcrypt Password Hashing
- Unique Password Salting
- Session-Based Authentication
- User Data Isolation
- Secure Login Validation
- Protected Routes

---

# Installation

## Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/Mini-SIEM-ML-Threat-Detection.git
```

---

## Navigate to Project

```bash
cd Mini-SIEM-ML-Threat-Detection
```

---

## Install Requirements

```bash
pip install -r requirements.txt
```

---

## Run Application

```bash
python app.py
```

---

# Screenshots

## Dashboard
Add dashboard screenshot inside:
```text
screenshots/dashboard.png
```

---

## Login Page
Add login screenshot inside:
```text
screenshots/login.png
```

---

## Threat Detection
Add detection screenshot inside:
```text
screenshots/detection.png
```

---

# Future Scope

- Cloud Deployment
- Advanced Threat Intelligence
- Live SIEM Integration
- Email Alert System
- AI-Based Threat Prediction
- Network Packet Monitoring
- Real-Time SOC Integration

---

# Academic Purpose

This project was developed for academic and educational purposes to demonstrate:

- SIEM Concepts
- Cybersecurity Monitoring
- Threat Detection Techniques
- Machine Learning in Cybersecurity
- Real-Time Log Analysis
- Hybrid Security Systems

---

# Author

## Melchi Joseph

BTech 4th Year  
Aspiring SOC & IAM Analyst  
Cybersecurity Enthusiast

---

# License

This project is developed for educational and academic purposes.
