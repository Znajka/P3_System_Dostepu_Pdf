# P3 System Dostepu PDF - Setup and Run Guide

## Step 1: Clone Repository
git clone https://github.com/Znajka/P3_System_Dostepu_Pdf.git cd P3_System_Dostepu_Pdf
## Step 2: Generate Secrets and Configuration
JWT_SECRET=$(openssl rand -base64 32) DB_PASSWORD=$(openssl rand -base64 32)
cat > backend/.env << EOF POSTGRES_DB=p3_system_db POSTGRES_USER=postgres POSTGRES_PASSWORD=$DB_PASSWORD SPRING_PROFILES_ACTIVE=docker APP_JWT_SECRET=$JWT_SECRET APP_JWT_EXPIRATION_MS=3600000 APP_REFRESH_TOKEN_EXPIRATION_MS=604800000 KMS_PROVIDER=vault KMS_ENDPOINT=http://vault:8200 KMS_AUTH_TOKEN=s.test-token VAULT_ROOT_TOKEN=root-token FASTAPI_ENV=docker FASTAPI_SERVICE_URL=https://fastapi-pdf-service:8443 FASTAPI_LOGGING_LEVEL=INFO FASTAPI_WORKERS=4 STORAGE_TYPE=local STORAGE_LOCAL_PATH=/data/encrypted-documents MAX_PDF_SIZE=104857600 APP_RATE_LIMIT_ENABLED=true APP_RATE_LIMIT_FAILED_ATTEMPTS=5 APP_RATE_LIMIT_WINDOW_MINUTES=15 APP_RATE_LIMIT_LOCKOUT_MINUTES=30 GRANT_EXPIRATION_ENABLED=true GRANT_EXPIRATION_INTERVAL_SECONDS=300 APP_SECURITY_IP_PINNING_ENABLED=true APP_LOGGING_LEVEL=INFO PGADMIN_EMAIL=admin@p3.local PGADMIN_PASSWORD=admin-password EOF

## Step 3: Generate SSL Certificates
mkdir -p backend/certs
CA Certificate
openssl genrsa -out backend/certs/ca.key 2048 openssl req -new -x509 -days 365 -key backend/certs/ca.key -out backend/certs/ca.crt -subj "/C=US/ST=State/L=City/O=P3/CN=P3-CA"
Spring Boot Certificate
openssl genrsa -out backend/certs/spring-boot.key 2048 openssl req -new -key backend/certs/spring-boot.key -out backend/certs/spring-boot.csr -subj "/C=US/ST=State/L=City/O=P3/CN=spring-boot-backend" openssl x509 -req -days 365 -in backend/certs/spring-boot.csr -CA backend/certs/ca.crt -CAkey backend/certs/ca.key -CAcreateserial -out backend/certs/spring-boot.crt
FastAPI Certificate
openssl genrsa -out backend/certs/fastapi.key 2048 openssl req -new -key backend/certs/fastapi.key -out backend/certs/fastapi.csr -subj "/C=US/ST=State/L=City/O=P3/CN=fastapi-pdf-service" openssl x509 -req -days 365 -in backend/certs/fastapi.csr -CA backend/certs/ca.crt -CAkey backend/certs/ca.key -CAcreateserial -out backend/certs/fastapi.crt
chmod 600 backend/certs/.key chmod 644 backend/certs/.crt
## Step 4: Create Data Directories
mkdir -p data/encrypted-documents data/postgres data/vault chmod 700 data/*
## Step 5: Start Docker Services
docker-compose up -d
Wait 2-3 minutes for services to start.

## Step 6: Verify Services Are Running
docker-compose ps
You should see 6 services running:
- postgres
- vault
- fastapi-pdf-service
- spring-boot
- frontend
- pgadmin

## Step 7: Create Test Users
Create Admin User
curl -X POST http://localhost:8080/api/auth/register 
-H "Content-Type: application/json" 
-d '{ "username": "admin", "email": "admin@example.com", "password": "AdminPassword123!" }'
Create Owner User
curl -X POST http://localhost:8080/api/auth/register 
-H "Content-Type: application/json" 
-d '{ "username": "owner", "email": "owner@example.com", "password": "OwnerPassword123!" }'
Create Regular User
curl -X POST http://localhost:8080/api/auth/register 
-H "Content-Type: application/json" 
-d '{ "username": "user", "email": "user@example.com", "password": "UserPassword123!" }'
## Step 8: Access the System in Browser

Open your browser and go to:

**Frontend Dashboard**: http://localhost:3000

Login with:
- Username: `admin`
- Password: `AdminPassword123!`

## Step 9: Upload a Document

1. Click "Upload Document"
2. Select any PDF file from your computer
3. Enter title and description
4. Click "Upload"

## Step 10: Grant Access to a User

1. Click on the uploaded document
2. Click "Grant Access"
3. Select a user from the dropdown
4. Set expiration date (e.g., 7 days from now)
5. Click "Grant"

## Step 11: View Document as User

1. Logout from admin account
2. Login as: username `user`, password `UserPassword123!`
3. Click on the document
4. Click "Open"
5. The PDF will open in the secure viewer (canvas-only, no download option)

## Accessing Other Services

| Service | URL |
|---------|-----|
| **Frontend** | http://localhost:3000 |
| **Spring Boot API Docs** | http://localhost:8080/swagger-ui.html |
| **PgAdmin Database** | http://localhost:5050 |
| **FastAPI API** | https://localhost:8443/docs |

## Stop the System
docker-compose down
## Stop and Remove All Data
docker-compose down -v
## View Logs
All services
docker-compose logs -f
Specific service
docker-compose logs -f spring-boot docker-compose logs -f fastapi-pdf-service docker-compose logs -f frontend
## Troubleshooting

**Port already in use:**
lsof -i :8080 kill -9 <PID>
**Services not starting:**
docker-compose logs docker-compose restart
**Database connection error:**
docker-compose down -v docker-compose up -d

---

**Done!** Your system is now running and accessible at http://localhost:3000
