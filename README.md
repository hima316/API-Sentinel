# API Sentinel – API Security Monitoring & Anomaly Detection

API Sentinel is a backend security monitoring system that detects suspicious API activity using rule-based detection and machine learning.

It monitors API requests, identifies unusual behaviour such as repeated failed logins, request bursts and endpoint probing, and generates security alerts for further investigation.

**[Live Demo](https://api-sentinel-fg9j.onrender.com)** · **[Swagger API Docs](https://api-sentinel-fg9j.onrender.com/docs)** · **[Health Check](https://api-sentinel-fg9j.onrender.com/health)**

## Features

- **Request Monitoring:** Collects request and response metadata such as client ID, endpoint, status code and processing time.
- **Rule-Based Detection:** Identifies repeated failed logins, unusually high request rates and endpoint probing.
- **ML-Based Detection:** Uses Isolation Forest to identify unusual traffic patterns based on client behaviour.
- **Alert Management:** Generates alerts and avoids duplicate alerts using cooldown periods.
- **Flexible Storage:** Supports in-memory storage and MongoDB Atlas for storing request logs and security alerts.

## Technology Stack

- **Language:** Python
- **Backend:** FastAPI
- **Machine Learning:** Scikit-learn (Isolation Forest)
- **Database:** MongoDB Atlas
- **Testing:** Pytest
- **Deployment:** Docker, Render

## Project Structure

```text
API-Sentinel/
├── app/
│   ├── core/          # Application configuration
│   ├── database/      # MongoDB connection
│   ├── middleware/    # Request monitoring
│   ├── ml/            # ML detection and features
│   ├── models/        # Data models and schemas
│   ├── repositories/  # Log and alert storage
│   ├── routes/        # API endpoints
│   └── rules/         # Rule-based detection
├── models/            # Trained ML model
├── reports/           # Simulation and evaluation results
├── scripts/           # Training, simulation and evaluation
├── tests/             # Automated tests
├── Dockerfile
├── docker-compose.yml
├── render.yaml
└── requirements.txt
```

## API Endpoints

| Endpoint | Description |
|---|---|
| `POST /api/login` | Simulates user authentication |
| `GET /api/products` | Returns sample product data |
| `GET /logs` | Retrieves request logs |
| `GET /alerts` | Retrieves security alerts |
| `GET /analysis/status` | Checks ML model status |
| `POST /analysis/run` | Runs anomaly analysis |
| `GET /health` | Checks application health |

Interactive API documentation is available at `/docs`.

## Running Locally

**1. Clone the repository**

```bash
git clone https://github.com/hima316/API-Sentinel.git
cd API-Sentinel
```

**2. Create a virtual environment and install dependencies**

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

**3. Start the application**

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**4. Open Swagger documentation**

http://127.0.0.1:8000/docs

The application uses in-memory storage by default, so MongoDB configuration is not required for a basic local run.

## Testing & Simulation

Run the automated test suite:

```bash
pytest -v
```

Generate simulated API traffic:

```bash
python scripts/simulate_traffic.py --base-url http://127.0.0.1:8000 --output reports/simulation_manifest.json
```

The simulator generates normal traffic and suspicious scenarios, including brute-force attempts, request bursts and endpoint probing.

## Evaluation

The detection system was evaluated using synthetic traffic with known labels.

A held-out test set of 700 windows was used to compare rule-based detection, Isolation Forest and their combination.

| Detection Method | Precision | Recall | F1 Score |
|---|---:|---:|---:|
| Rule-Based | 1.00 | 0.74 | 0.8506 |
| Isolation Forest | 0.8571 | 0.75 | 0.8000 |
| Hybrid Detection | 0.8889 | 1.00 | 0.9412 |


*Note: These results are based on synthetic test data*


## Limitations

- API Sentinel currently monitors and reports suspicious activity; it does not automatically block requests or attackers.
- Evaluation is based on synthetic traffic and requires further validation with real-world data.

## Future Improvements

- Integrate automated IP blocking and rate limiting.
- Add real-time security notifications.
- Improve detection using real-world traffic data.
- Add a security dashboard for monitoring alerts.