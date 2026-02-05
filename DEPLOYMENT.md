# 🚀 Production Deployment Guide

## Pre-Deployment Checklist

### 1. Code Review
- [ ] Review all security configurations
- [ ] Remove demo/test accounts
- [ ] Remove debug statements
- [ ] Update CORS origins to production domains
- [ ] Set appropriate rate limits
- [ ] Review all environment variables

### 2. Security Configuration
- [ ] Generate strong SECRET_KEY (64+ characters)
- [ ] Enable SESSION_COOKIE_SECURE=True
- [ ] Uncomment Talisman configuration
- [ ] Configure CSP headers for your domain
- [ ] Set up SSL/TLS certificates
- [ ] Configure firewall rules

### 3. Database
- [ ] Migrate from SQLite to PostgreSQL (recommended)
- [ ] Set up database backups
- [ ] Configure connection pooling
- [ ] Set appropriate user permissions
- [ ] Test database restore procedure

### 4. Infrastructure
- [ ] Set up load balancer (if applicable)
- [ ] Configure CDN for static assets
- [ ] Set up monitoring and alerting
- [ ] Configure log aggregation
- [ ] Set up automated backups
- [ ] Configure auto-scaling (if needed)

---

## Deployment Options

### Option 1: Traditional Server (Ubuntu/Debian)

#### Step 1: Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3.10 python3-pip python3-venv nginx certbot python3-certbot-nginx postgresql postgresql-contrib redis-server

# Create application user
sudo useradd -m -s /bin/bash coffeeapp
sudo usermod -aG sudo coffeeapp
```

#### Step 2: PostgreSQL Setup

```bash
# Switch to postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE coffee_shop;
CREATE USER coffeeapp WITH PASSWORD 'your-secure-password';
GRANT ALL PRIVILEGES ON DATABASE coffee_shop TO coffeeapp;
\q
```

#### Step 3: Application Setup

```bash
# Switch to app user
sudo su - coffeeapp

# Clone/upload application
cd /home/coffeeapp
# Upload your secure_coffee_shop files here

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
nano .env
```

**.env for Production:**
```bash
SECRET_KEY=your-64-character-minimum-random-secret-key-here
FLASK_ENV=production
FLASK_DEBUG=False
DATABASE_URL=postgresql://coffeeapp:your-secure-password@localhost:5432/coffee_shop
SESSION_COOKIE_SECURE=True
RATE_LIMIT_STORAGE_URL=redis://localhost:6379
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

#### Step 4: Systemd Service

```bash
# Create service file
sudo nano /etc/systemd/system/coffeeapp.service
```

```ini
[Unit]
Description=Coffee Shop Application
After=network.target postgresql.service redis.service

[Service]
Type=notify
User=coffeeapp
Group=coffeeapp
WorkingDirectory=/home/coffeeapp/secure_coffee_shop
Environment="PATH=/home/coffeeapp/venv/bin"
ExecStart=/home/coffeeapp/venv/bin/gunicorn \
    --workers 4 \
    --worker-class gevent \
    --bind unix:/home/coffeeapp/secure_coffee_shop/coffee.sock \
    --access-logfile /home/coffeeapp/logs/access.log \
    --error-logfile /home/coffeeapp/logs/error.log \
    --log-level info \
    app:app

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Create log directory
mkdir -p /home/coffeeapp/logs

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable coffeeapp
sudo systemctl start coffeeapp
sudo systemctl status coffeeapp
```

#### Step 5: Nginx Configuration

```bash
sudo nano /etc/nginx/sites-available/coffeeapp
```

```nginx
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=general:10m rate=100r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=50r/m;

# Upstream
upstream coffee_app {
    server unix:/home/coffeeapp/secure_coffee_shop/coffee.sock fail_timeout=0;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Max body size
    client_max_body_size 16M;

    # Logging
    access_log /var/log/nginx/coffeeapp.access.log;
    error_log /var/log/nginx/coffeeapp.error.log;

    # Static files
    location /static {
        alias /home/coffeeapp/secure_coffee_shop/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # API endpoints with rate limiting
    location /api/login {
        limit_req zone=login burst=2 nodelay;
        limit_req_status 429;
        proxy_pass http://coffee_app;
        include /etc/nginx/proxy_params;
    }

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://coffee_app;
        include /etc/nginx/proxy_params;
    }

    # General pages
    location / {
        limit_req zone=general burst=50 nodelay;
        limit_req_status 429;
        proxy_pass http://coffee_app;
        include /etc/nginx/proxy_params;
    }
}
```

```bash
# Create proxy params
sudo nano /etc/nginx/proxy_params
```

```nginx
proxy_set_header Host $http_host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_redirect off;
proxy_buffering off;
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/coffeeapp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

#### Step 6: SSL Certificate

```bash
# Get Let's Encrypt certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

#### Step 7: Firewall

```bash
# Configure UFW
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
sudo ufw status
```

#### Step 8: Fail2Ban

```bash
# Install fail2ban
sudo apt install -y fail2ban

# Create custom jail
sudo nano /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = admin@yourdomain.com
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = 22

[nginx-http-auth]
enabled = true

[nginx-limit-req]
enabled = true
port = http,https
logpath = /var/log/nginx/*error.log
```

```bash
# Start fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
sudo fail2ban-client status
```

---

### Option 2: Docker Deployment

#### Dockerfile

```dockerfile
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn gevent

# Copy application
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/', timeout=2)"

# Run application
CMD ["gunicorn", "--workers", "4", "--worker-class", "gevent", "--bind", "0.0.0.0:8000", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
```

#### docker-compose.yml

```yaml
version: '3.8'

services:
  app:
    build: .
    container_name: coffee_app
    restart: always
    ports:
      - "8000:8000"
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - DATABASE_URL=postgresql://postgres:${DB_PASSWORD}@db:5432/coffee_shop
      - FLASK_ENV=production
      - RATE_LIMIT_STORAGE_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs
    networks:
      - app_network

  db:
    image: postgres:15-alpine
    container_name: coffee_db
    restart: always
    environment:
      - POSTGRES_DB=coffee_shop
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - app_network

  redis:
    image: redis:7-alpine
    container_name: coffee_redis
    restart: always
    networks:
      - app_network

  nginx:
    image: nginx:alpine
    container_name: coffee_nginx
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - app
    networks:
      - app_network

volumes:
  postgres_data:

networks:
  app_network:
    driver: bridge
```

```bash
# Deploy
docker-compose up -d

# View logs
docker-compose logs -f app

# Scale workers
docker-compose up -d --scale app=3
```

---

### Option 3: Cloud Platform (AWS Example)

#### AWS Elastic Beanstalk

```bash
# Install EB CLI
pip install awsebcli

# Initialize
eb init -p python-3.10 coffee-shop-app

# Create environment
eb create coffee-shop-prod \
    --database.engine postgres \
    --database.username coffeeapp \
    --envvars SECRET_KEY=your-secret-key,FLASK_ENV=production

# Deploy
eb deploy

# Set environment variables
eb setenv SESSION_COOKIE_SECURE=True CORS_ORIGINS=https://yourdomain.com

# View logs
eb logs
```

---

## Post-Deployment

### 1. Monitoring Setup

```bash
# Install monitoring agent (example: Datadog)
DD_API_KEY=your-key bash -c "$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script.sh)"

# Configure application monitoring
sudo nano /etc/datadog-agent/conf.d/gunicorn.d/conf.yaml
```

### 2. Log Rotation

```bash
# Create logrotate config
sudo nano /etc/logrotate.d/coffeeapp
```

```
/home/coffeeapp/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 coffeeapp coffeeapp
    sharedscripts
    postrotate
        systemctl reload coffeeapp > /dev/null 2>&1 || true
    endscript
}
```

### 3. Database Backups

```bash
# Create backup script
nano /home/coffeeapp/backup.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/home/coffeeapp/backups"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup database
pg_dump -U coffeeapp coffee_shop | gzip > $BACKUP_DIR/db_backup_$DATE.sql.gz

# Keep only last 30 days
find $BACKUP_DIR -name "db_backup_*.sql.gz" -mtime +30 -delete

# Upload to S3 (optional)
# aws s3 cp $BACKUP_DIR/db_backup_$DATE.sql.gz s3://your-bucket/backups/
```

```bash
# Make executable
chmod +x /home/coffeeapp/backup.sh

# Add to crontab
crontab -e
# Add: 0 2 * * * /home/coffeeapp/backup.sh
```

### 4. Health Checks

```bash
# Create health check script
nano /home/coffeeapp/health_check.sh
```

```bash
#!/bin/bash
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/)
if [ $RESPONSE != "200" ]; then
    echo "Application is down! HTTP Status: $RESPONSE"
    # Send alert (email, Slack, PagerDuty, etc.)
    systemctl restart coffeeapp
fi
```

```bash
# Add to crontab (every 5 minutes)
*/5 * * * * /home/coffeeapp/health_check.sh
```

### 5. Security Monitoring

```bash
# Monitor security logs
tail -f /home/coffeeapp/secure_coffee_shop/security.log | grep -E "CRITICAL|HIGH"

# Set up alerts for critical events
# (Use log aggregation service like ELK, Splunk, or cloud provider's solution)
```

---

## Troubleshooting

### Application won't start
```bash
# Check systemd logs
sudo journalctl -u coffeeapp -n 50

# Check application logs
tail -f /home/coffeeapp/logs/error.log

# Check permissions
ls -la /home/coffeeapp/secure_coffee_shop/
```

### Database connection issues
```bash
# Test PostgreSQL connection
psql -U coffeeapp -d coffee_shop -h localhost

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-15-main.log
```

### Nginx issues
```bash
# Test configuration
sudo nginx -t

# Check logs
sudo tail -f /var/log/nginx/coffeeapp.error.log

# Check if socket exists
ls -la /home/coffeeapp/secure_coffee_shop/coffee.sock
```

---

## Performance Tuning

### Gunicorn Workers
```bash
# Calculate optimal workers: (2 x CPU cores) + 1
# For 4 cores: (2 x 4) + 1 = 9 workers
gunicorn --workers 9 --worker-class gevent ...
```

### PostgreSQL Tuning
```bash
# Edit postgresql.conf
sudo nano /etc/postgresql/15/main/postgresql.conf

# Recommended settings for 4GB RAM server:
shared_buffers = 1GB
effective_cache_size = 3GB
maintenance_work_mem = 256MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 10MB
min_wal_size = 1GB
max_wal_size = 4GB
```

### Redis Configuration
```bash
# Edit redis.conf
sudo nano /etc/redis/redis.conf

# Recommended settings:
maxmemory 256mb
maxmemory-policy allkeys-lru
```

---

## Maintenance Schedule

**Daily**:
- Monitor error logs
- Check disk space
- Review security events

**Weekly**:
- Test backups
- Review performance metrics
- Update dependencies (if needed)
- Check SSL certificate expiration

**Monthly**:
- Full security audit
- Performance optimization
- Review and rotate logs
- Test disaster recovery

---

**Questions or Issues?**  
Contact: devops@yourdomain.com
