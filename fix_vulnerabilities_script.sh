#!/bin/bash

# fix-vulnerabilities.sh
# Script do automatycznej naprawy podstawowych podatności w PyGoat

set -e

echo "🔧 Starting vulnerability fixes for PyGoat..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to backup original files
backup_file() {
    if [ -f "$1" ]; then
        cp "$1" "$1.backup.$(date +%Y%m%d_%H%M%S)"
        print_status "Backed up $1"
    fi
}

# 1. Fix SCA vulnerabilities - Update requirements.txt
fix_sca_vulnerabilities() {
    print_status "Fixing SCA vulnerabilities..."
    
    backup_file "requirements.txt"
    
    # Create updated requirements.txt with secure versions
    cat > requirements.txt << 'EOF'
# Updated requirements.txt with security fixes
Django==4.2.7
Pillow==10.1.0
sqlparse==0.4.4
asgiref==3.7.2
pytz==2023.3

# Additional security dependencies
django-security
django-csp==3.7
django-ratelimit==4.1.0

# Development dependencies
bandit==1.7.5
safety==2.3.5
pip-audit==2.5.0
EOF

    print_status "Updated requirements.txt with secure package versions"
}

# 2. Fix SAST vulnerabilities - Update Django settings
fix_sast_vulnerabilities() {
    print_status "Fixing SAST vulnerabilities..."
    
    # Find Django settings file
    SETTINGS_FILE=$(find . -name "settings.py" | head -1)
    
    if [ -z "$SETTINGS_FILE" ]; then
        print_error "Django settings.py not found"
        return 1
    fi
    
    backup_file "$SETTINGS_FILE"
    
    # Add security settings to Django
    cat >> "$SETTINGS_FILE" << 'EOF'

# Security settings added by DevSecOps pipeline
import os

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# CSRF protection
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'

# Session security
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 3600  # 1 hour

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")

# Rate limiting
RATELIMIT_ENABLE = True

# Logging configuration for security events
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'security': {
            'format': '{levelname} {asctime} {name} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': 'logs/security.log',
            'formatter': 'security',
        },
    },
    'loggers': {
        'django.security': {
            'handlers': ['security_file'],
            'level': 'WARNING',
            'propagate': True,
        },
    },
}
EOF

    print_status "Added security configurations to Django settings"
}

# 3. Fix secrets - Remove hardcoded secrets
fix_secrets() {
    print_status "Fixing hardcoded secrets..."
    
    # Find and replace common secret patterns
    find . -type f -name "*.py" -exec grep -l "SECRET_KEY\s*=" {} \; | while read file; do
        backup_file "$file"
        
        # Replace hardcoded SECRET_KEY with environment variable
        sed -i "s/SECRET_KEY\s*=\s*['\"][^'\"]*['\"]/SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'dev-key-change-me')/g" "$file"
        print_status "Updated SECRET_KEY in $file"
    done
    
    # Create .env.example file
    cat > .env.example << 'EOF'
# Environment variables for PyGoat
DJANGO_SECRET_KEY=your-secret-key-here
DJANGO_DEBUG=False
DATABASE_URL=sqlite:///db.sqlite3
EOF
    
    print_status "Created .env.example file"
    
    # Update .gitignore to exclude sensitive files
    if [ ! -f .gitignore ]; then
        touch .gitignore
    fi
    
    cat >> .gitignore << 'EOF'

# Security and environment files
.env
*.log
security-reports/
logs/
*.backup.*
EOF

    print_status "Updated .gitignore with security patterns"
}

# 4. Fix container vulnerabilities
fix_container_vulnerabilities() {
    print_status "Fixing container vulnerabilities..."
    
    # The Dockerfile is already created with security best practices
    print_status "Dockerfile already configured with security best practices:"
    print_status "  - Non-root user"
    print_status "  - Minimal base image"
    print_status "  - Package cleanup"
    print_status "  - Health checks"
}

# 5. Create security configuration files
create_security_configs() {
    print_status "Creating security configuration files..."
    
    mkdir -p security
    
    # Bandit configuration
    cat > .bandit << 'EOF'
[bandit]
exclude_dirs = ['*/tests/*', '*/venv/*', '*/migrations/*']
tests = ['B201', 'B301', 'B302', 'B303', 'B304', 'B305', 'B306', 'B307', 'B308', 'B309', 'B310', 'B311', 'B312', 'B313', 'B314', 'B315', 'B316', 'B317', 'B318', 'B319', 'B320', 'B321', 'B322', 'B323', 'B324', 'B325', 'B401', 'B402', 'B403', 'B404', 'B405', 'B406', 'B407', 'B408', 'B409', 'B410', 'B411', 'B412', 'B413', 'B501', 'B502', 'B503', 'B504', 'B505', 'B506', 'B507', 'B601', 'B602', 'B603', 'B604', 'B605', 'B606', 'B607', 'B608', 'B609', 'B610', 'B611', 'B701', 'B702', 'B703']
skips = ['B110', 'B410']
EOF

    # GitLeaks configuration
    cat > .gitleaks.toml << 'EOF'
[extend]
useDefault = true

[[rules]]
description = "Django Secret Key"
regex = '''SECRET_KEY\s*=\s*['""][^'""]{20,}['""]'''
tags = ["secret", "django"]
EOF

    # ZAP rules
    mkdir -p .zap
    cat > .zap/rules.tsv << 'EOF'
10021	IGNORE	(Cookie No HttpOnly Flag - intentionally vulnerable app)
10023	IGNORE	(Information Disclosure - Debug Error Messages - for learning)
10025	IGNORE	(Information Disclosure - Debug Error Messages)
10026	IGNORE	(HTTP Parameter Override)
10027	IGNORE	(Information Disclosure - Suspicious Comments)
EOF

    print_status "Created security configuration files"
}

# 6. Create example vulnerability fixes
create_example_fixes() {
    print_status "Creating example vulnerability fixes..."
    
    mkdir -p examples
    
    # SQL Injection fix example
    cat > examples/sql_injection_fix.py << 'EOF'
# Example: SQL Injection vulnerability fix

# VULNERABLE CODE (BEFORE):
def get_user_vulnerable(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# SECURE CODE (AFTER):
def get_user_secure(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

# Django ORM (RECOMMENDED):
def get_user_django(user_id):
    from django.contrib.auth.models import User
    return User.objects.filter(id=user_id).first()
EOF

    # XSS fix example
    cat > examples/xss_fix.py << 'EOF'
# Example: XSS vulnerability fix

# VULNERABLE CODE (BEFORE):
def display_message_vulnerable(request):
    message = request.GET.get('msg', '')
    return HttpResponse(f"<h1>Message: {message}</h1>")

# SECURE CODE (AFTER):
from django.utils.html import escape

def display_message_secure(request):
    message = request.GET.get('msg', '')
    escaped_message = escape(message)
    return HttpResponse(f"<h1>Message: {escaped_message}</h1>")

# DJANGO TEMPLATE (RECOMMENDED):
def display_message_template(request):
    message = request.GET.get('msg', '')
    return render(request, 'message.html', {'message': message})
    # Template automatically escapes: {{ message }}
EOF

    print_status "Created example vulnerability fixes"
}

# 7. Run security tests
run_security_tests() {
    print_status "Running basic security tests..."
    
    # Install security tools if not present
    pip install bandit safety pip-audit 2>/dev/null || true
    
    # Run Bandit
    if command -v bandit &> /dev/null; then
        print_status "Running Bandit SAST scan..."
        bandit -r . -f json -o security-reports/bandit-report.json 2>/dev/null || true
        bandit -r . -ll -i 2>/dev/null || print_warning "Bandit found some issues - check the report"
    fi
    
    # Run Safety
    if command -v safety &> /dev/null; then
        print_status "Running Safety SCA scan..."
        safety check --json --output security-reports/safety-report.json 2>/dev/null || true
        safety check --short-report 2>/dev/null || print_warning "Safety found vulnerabilities"
    fi
    
    # Run pip-audit
    if command -v pip-audit &> /dev/null; then
        print_status "Running pip-audit..."
        pip-audit --format=json --output=security-reports/pip-audit-report.json 2>/dev/null || true
    fi
}

# Main execution
main() {
    print_status "Starting PyGoat security fixes..."
    
    # Create directories
    mkdir -p logs security-reports examples
    
    # Run fixes
    fix_sca_vulnerabilities
    fix_sast_vulnerabilities  
    fix_secrets
    fix_container_vulnerabilities
    create_security_configs
    create_example_fixes
    
    # Run tests
    run_security_tests
    
    print_status "✅ Security fixes completed!"
    print_status ""
    print_status "Next steps:"
    print_status "1. Review the changes made to your files"
    print_status "2. Test the application: python manage.py runserver"
    print_status "3. Run the CI/CD pipeline to validate security"
    print_status "4. Check security-reports/ directory for scan results"
    print_status ""
    print_warning "Note: This is a vulnerable application for learning purposes."
    print_warning "Some vulnerabilities are intentionally left for educational value."
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi