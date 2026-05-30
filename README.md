# SOC Security System

A comprehensive Security Operations Center (SOC) solution built with **FastAPI**, **React**, and **Machine Learning** for real-time security monitoring, anomaly detection, and threat analysis.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.9+-blue)
![Node.js](https://img.shields.io/badge/node.js-16+-green)

---

## 🎯 Features

### Core Capabilities
- **Real-time Security Monitoring** - Live dashboard with security metrics and alerts
- **Anomaly Detection** - ML-powered detection of suspicious patterns and behaviors
- **Log Analysis** - Comprehensive log ingestion and analysis
- **Alert Management** - Intelligent alerting system with severity levels
- **WebSocket Support** - Real-time updates and live streaming
- **User Authentication** - JWT-based secure authentication
- **Rate Limiting** - Built-in protection against brute force attacks
- **SSRF Protection** - Server-side request forgery guards
- **Input Sanitization** - XSS and injection attack prevention
- **Audit Logging** - Complete audit trail of all operations
- **Prometheus Metrics** - Full observability and monitoring

### Security Features
- Security headers middleware
- Input validation and sanitization
- Role-based access control (RBAC)
- Password hashing and encryption
- CORS protection
- Request rate limiting

---

## 🏗️ Architecture

### Backend Stack
- **Framework**: FastAPI (Python)
- **Database**: PostgreSQL with Alembic migrations
- **ML/Analytics**: scikit-learn for anomaly detection
- **Monitoring**: Prometheus metrics
- **Authentication**: JWT tokens
- **API**: RESTful API + WebSocket

### Frontend Stack
- **Framework**: React with TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS
- **Components**: Recharts for visualizations
- **HTTP Client**: Axios
- **Icons**: Lucide React

### Deployment
- **Containerization**: Docker & Docker Compose
- **Web Server**: Nginx (frontend)
- **ASGI Server**: Uvicorn (backend)
- **Reverse Proxy**: Nginx

---

## 📋 Project Structure

```
SOC-Security-System/
├── backend/                          # FastAPI Backend
│   ├── app/
│   │   ├── main.py                  # Application entry point
│   │   ├── database/                # Database configuration
│   │   ├── models.py                # SQLAlchemy models
│   │   ├── routes/                  # API endpoints
│   │   │   ├── auth.py              # Authentication routes
│   │   │   ├── logs.py              # Log management
│   │   │   ├── alerts.py            # Alert routes
│   │   │   ├── analyze.py           # Analysis endpoints
│   │   │   └── websocket.py         # WebSocket connections
│   │   ├── services/                # Business logic
│   │   │   ├── anomaly_detection.py # ML anomaly detection
│   │   │   ├── alerts_engine.py     # Alert processing
│   │   │   ├── scoring.py           # Risk scoring
│   │   │   ├── jwt_handler.py       # JWT management
│   │   │   └── preprocessing.py     # Data preprocessing
│   │   ├── middleware/              # Custom middleware
│   │   │   ├── audit_logger.py      # Audit logging
│   │   │   ├── rate_limiter.py      # Rate limiting
│   │   │   └── security_headers.py  # Security headers
│   │   ├── schemas/                 # Pydantic models
│   │   ├── security/                # Security utilities
│   │   │   ├── input_sanitizer.py   # Input validation
│   │   │   ├── permissions.py       # Access control
│   │   │   └── ssrf_guard.py        # SSRF protection
│   │   └── monitoring/              # Metrics and monitoring
│   ├── alembic/                     # Database migrations
│   ├── tests/                       # Unit tests
│   ├── scripts/                     # Utility scripts
│   ├── data/                        # Sample data
│   ├── requirements.txt             # Python dependencies
│   ├── Dockerfile                   # Backend container
│   └── README.md                    # Backend documentation
│
├── frontend/                         # React Frontend
│   ├── src/
│   │   ├── main.tsx                 # Entry point
│   │   ├── App.tsx                  # Main component
│   │   ├── pages/                   # Page components
│   │   │   ├── Dashboard.jsx        # Main dashboard
│   │   │   ├── Logs.jsx             # Log viewer
│   │   │   ├── Alerts.jsx           # Alert management
│   │   │   ├── Analyze.jsx          # Analysis tools
│   │   │   └── Login.jsx            # Authentication
│   │   ├── components/              # Reusable components
│   │   │   ├── ScoreBar.jsx         # Risk score display
│   │   │   ├── AlertToast.jsx       # Notifications
│   │   │   ├── StatCard.jsx         # Statistics card
│   │   │   ├── LevelBadge.jsx       # Severity badge
│   │   │   └── Sidebar.jsx          # Navigation
│   │   ├── services/                # API services
│   │   │   └── api.js               # HTTP client
│   │   ├── hooks/                   # Custom hooks
│   │   │   └── useWebSocket.js      # WebSocket hook
│   │   ├── context/                 # Context providers
│   │   │   └── AuthContext.jsx      # Auth state
│   │   └── utils/                   # Utilities
│   │       └── format.js            # Formatting helpers
│   ├── public/                      # Static assets
│   ├── package.json                 # Dependencies
│   ├── vite.config.ts               # Vite configuration
│   ├── tsconfig.json                # TypeScript config
│   ├── tailwind.config.js           # Tailwind configuration
│   ├── Dockerfile                   # Frontend container
│   ├── nginx.conf                   # Nginx configuration
│   └── README.md                    # Frontend documentation
│
├── monitoring/                       # Monitoring Configuration
│   ├── prometheus.yml               # Prometheus config
│   └── alerts_rules.yml             # Alert rules
│
├── docker-compose.yml               # Multi-container setup
├── .gitignore                       # Git ignore rules
└── README.md                        # This file
```

---

## 🚀 Quick Start

### Prerequisites
- **Docker** & **Docker Compose** (recommended)
- **Python 3.9+** (for local development)
- **Node.js 16+** (for local frontend development)
- **PostgreSQL** (if not using Docker)

### Option 1: Docker Compose (Recommended)

1. **Clone the repository**
   ```bash
   git clone https://github.com/alajouili/SOC-Security-System.git
   cd SOC-Security-System
   ```

2. **Build and start services**
   ```bash
   docker-compose up -d
   ```

3. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

### Option 2: Local Development

#### Backend Setup
```bash
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup database
alembic upgrade head

# Generate security keys
python generate_keys.py

# Run the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend Setup
```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

---

## 🔐 Configuration

### Environment Variables

Create `.env` files in both `backend/` and `frontend/` directories:

**Backend (.env)**
```env
DATABASE_URL=postgresql://user:password@localhost:5432/soc_db
JWT_SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
ENVIRONMENT=development
```

**Frontend (.env)**
```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

### Database Setup
```bash
# Run migrations
cd backend
alembic upgrade head

# Seed sample data (optional)
python generate_data.py
```

---

## 📊 API Endpoints

### Authentication
- `POST /api/auth/login` - Login and get JWT token
- `POST /api/auth/register` - Register new user
- `POST /api/auth/refresh` - Refresh access token

### Logs
- `GET /api/logs` - List all logs
- `GET /api/logs/{id}` - Get specific log
- `POST /api/logs` - Create new log entry
- `DELETE /api/logs/{id}` - Delete log

### Alerts
- `GET /api/alerts` - List all alerts
- `POST /api/alerts` - Create alert
- `PATCH /api/alerts/{id}` - Update alert status
- `DELETE /api/alerts/{id}` - Delete alert

### Analysis
- `POST /api/analyze/detect-anomalies` - Run anomaly detection
- `GET /api/analyze/metrics` - Get current metrics
- `POST /api/analyze/score` - Calculate risk score

### WebSocket
- `WS /ws` - Real-time updates and notifications

### Monitoring
- `GET /metrics` - Prometheus metrics

---

## 🧪 Testing

### Run Backend Tests
```bash
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test
pytest tests/test_anomaly_detection.py
```

### Run Frontend Tests (if configured)
```bash
cd frontend
npm test
```

---

## 🔍 Monitoring & Observability

### Prometheus Metrics
Access metrics at: `http://localhost:8000/metrics`

**Key Metrics:**
- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request latency
- `anomalies_detected_total` - Total anomalies detected
- `alerts_created_total` - Total alerts created
- `logs_processed_total` - Logs processed

### View Logs
```bash
# Backend logs
docker-compose logs backend -f

# Frontend logs
docker-compose logs frontend -f

# Database logs
docker-compose logs db -f
```

---

## 🔄 ML Model Training

Train the anomaly detection model:
```bash
cd backend
python scripts/train_model.sh
```

This will:
1. Process historical log data
2. Extract features
3. Train isolation forest model
4. Save model to `backend/app/model/`

---

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Free up ports
lsof -i :3000          # Frontend
lsof -i :8000          # Backend
lsof -i :5432          # Database
kill -9 <PID>
```

### Database Connection Issues
```bash
# Check database status
docker-compose exec db pg_isready

# Reset database
docker-compose down -v
docker-compose up -d
```

### WebSocket Connection Failed
- Ensure WebSocket server is running on port 8000
- Check browser console for connection errors
- Verify firewall rules

### High Memory Usage
```bash
# Clear Docker cache
docker system prune -a --volumes

# Restart services
docker-compose restart
```

---

## 📈 Performance Tuning

### Database Optimization
- Add indexes on frequently queried columns
- Use connection pooling
- Archive old logs regularly

### ML Model Optimization
- Increase `n_estimators` in Isolation Forest for better accuracy
- Reduce `contamination` parameter for fewer false positives
- Use feature selection to improve performance

### Frontend Optimization
- Enable gzip compression in Nginx
- Use code splitting with Vite
- Implement lazy loading for components

---

## 🔄 Deployment

### Production Deployment
1. Update environment variables for production
2. Build Docker images
   ```bash
   docker-compose -f docker-compose.yml build
   ```

3. Deploy using Docker Swarm or Kubernetes
4. Configure SSL/TLS certificates
5. Set up monitoring and alerting

### Kubernetes Deployment
See `k8s/` directory for Kubernetes manifests (if available)

---

## 📚 Documentation

- [Backend README](./backend/README.md) - Detailed backend documentation
- [Frontend README](./frontend/README.md) - Frontend-specific details
- API Docs: http://localhost:8000/docs (Swagger UI)
- ReDoc: http://localhost:8000/redoc

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards
- Follow PEP 8 for Python
- Use ESLint for JavaScript/TypeScript
- Write tests for new features
- Update documentation

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Authors

- **Lead Developer**: [alajouili](https://github.com/alajouili)

---

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/alajouili/SOC-Security-System/issues)
- **Discussions**: [GitHub Discussions](https://github.com/alajouili/SOC-Security-System/discussions)

---

## 🎓 Learning Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://react.dev/)
- [Docker Documentation](https://docs.docker.com/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [scikit-learn Anomaly Detection](https://scikit-learn.org/stable/modules/outlier_detection.html)

---

## 🔐 Security Considerations

- Keep dependencies updated: `pip install --upgrade -r requirements.txt`
- Rotate JWT secrets regularly
- Use strong database passwords
- Enable HTTPS in production
- Implement rate limiting
- Regular security audits
- Keep logs secure and backed up

---

## 🚀 Roadmap

- [ ] Integration with external SIEM systems
- [ ] Advanced threat intelligence feeds
- [ ] Machine learning model improvements
- [ ] Compliance reporting (GDPR, HIPAA, PCI-DSS)
- [ ] Multi-tenancy support
- [ ] Mobile app
- [ ] Advanced visualization dashboards
- [ ] Automated incident response

---

## 📊 Performance Metrics

- **API Response Time**: < 200ms (p95)
- **WebSocket Latency**: < 100ms
- **Anomaly Detection**: Real-time processing
- **Uptime Target**: 99.9%

---

**Last Updated**: May 30, 2026

**Repository**: [github.com/alajouili/SOC-Security-System](https://github.com/alajouili/SOC-Security-System)