# PyGoat DevSecOps Implementation

## 🎯 Cel Projektu

Implementacja kompletnego pipeline'u DevSecOps dla podatnej aplikacji PyGoat, demonstrująca integrację testów bezpieczeństwa w proces CI/CD.

## 🚀 Szybki Start

### 1. Przygotowanie Repozytorium

```bash
# Sklonuj PyGoat
git clone https://github.com/adeyosemanputra/pygoat.git
cd pygoat

# Utwórz nową gałąź dla DevSecOps
git checkout -b devsecops-implementation

# Utwórz strukturę katalogów
mkdir -p .github/workflows security scripts examples logs security-reports
```

### 2. Dodanie Plików Konfiguracyjnych

Skopiuj pliki z tego projektu do odpowiednich lokalizacji:

```bash
# GitHub Actions workflow
cp devsecops.yml .github/workflows/

# Docker configuration
cp Dockerfile ./
cp docker-compose.yml ./

# Security scripts
cp fix-vulnerabilities.sh scripts/
chmod +x scripts/fix-vulnerabilities.sh
```

### 3. Konfiguracja Secrets w GitHub

W ustawieniach repozytorium GitHub, dodaj następujące secrets:

- `DOCKER_USERNAME` - nazwa użytkownika Docker Hub
- `DOCKER_PASSWORD` - token dostępu Docker Hub

### 4. Uruchomienie Napraw Bezpieczeństwa

```bash
# Uruchom skrypt naprawy podatności
./scripts/fix-vulnerabilities.sh

# Zainstaluj zaktualizowane zależności
pip install -r requirements.txt

# Uruchom testy lokalne
python manage.py migrate
python manage.py runserver
```

## 🛡️ Pipeline Bezpieczeństwa

### Etapy Skanowania

#### 1. SCA (Software Composition Analysis)
- **Narzędzia**: Safety, pip-audit
- **Cel**: Wykrywanie podatnych zależności
- **Kryteria**: Naprawienie min. 2-3 podatności HIGH/CRITICAL

#### 2. SAST (Static Application Security Testing)
- **Narzędzia**: Bandit, Semgrep
- **Cel**: Analiza kodu źródłowego
- **Kryteria**: Naprawienie min. 2-3 podatności HIGH/CRITICAL

#### 3. Secrets Scanning
- **Narzędzia**: GitLeaks, TruffleHog
- **Cel**: Wykrywanie sekretów w kodzie
- **Kryteria**: Usunięcie/przeniesienie min. 2-3 znalezisk

#### 4. Container Security
- **Narzędzia**: Trivy
- **Cel**: Skanowanie obrazów Docker
- **Kryteria**: Naprawienie min. 2-3 podatności HIGH/CRITICAL

#### 5. DAST (Dynamic Application Security Testing)
- **Narzędzia**: OWASP ZAP, Nikto
- **Cel**: Testowanie działającej aplikacji
- **Kryteria**: Naprawienie min. 2-3 podatności HIGH/CRITICAL

## 📋 Przewidywane Podatności i Naprawy

### SCA Vulnerabilities

**Przed naprawą:**
```
Django==3.1.0         # CVE-2021-44420, CVE-2021-45115
Pillow==7.0.0         # CVE-2021-25287, CVE-2021-25288
sqlparse==0.4.1       # CVE-2021-32839
```

**Po naprawie:**
```
Django==4.2.7         # Latest LTS version
Pillow==10.1.0        # Security patches applied
sqlparse==0.4.4       # Vulnerability fixed
```

### SAST Vulnerabilities

**1. Hardcoded Secret Key**
```python
# PRZED (podatne)
SECRET_KEY = 'django-insecure-hardcoded-key-123'

# PO (bezpieczne)
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'dev-key-change-me')
```

**2. Missing Security Headers**
```python
# DODANE do settings.py
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
```

**3. SQL Injection (przykład)**
```python
# PRZED (podatne)
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)

# PO (bezpieczne)
def get_user(user_id):
    from django.contrib.auth.models import User
    return User.objects.filter(id=user_id).first()
```

### Container Security Vulnerabilities

**1. Running as Root**
```dockerfile
# PRZED (niebezpieczne)
FROM python:3.9
USER root

# PO (bezpieczne)
FROM python:3.9-slim
RUN groupadd -r pygoat && useradd -r -g pygoat pygoat
USER pygoat
```

**2. Vulnerable Base Image**
```dockerfile
# PRZED
FROM python:3.9

# PO
FROM python:3.9.18-slim-bullseye  # Specific secure version
```

### Secrets Scanning

**Wykryte i naprawione:**
1. Hardcoded Django SECRET_KEY
2. Database credentials in code
3. API keys w komentarzach

## 🔧 Lokalne Testowanie

### Uruchomienie Security Scans

```bash
# SCA Scan
pip install safety pip-audit
safety check
pip-audit

# SAST Scan
pip install bandit semgrep
bandit -r .
semgrep --config=auto .

# Container Scan
docker build -t pygoat-local .
trivy image pygoat-local

# DAST Scan (wymaga uruchomionej aplikacji)
docker-compose up -d
docker run -t owasp/zap2docker-stable zap-baseline.py -t http://host.docker.internal:8000
```

### Development z Security

```bash
# Uruchom z profilem security
docker-compose --profile security up

# Monitoring logów bezpieczeństwa
tail -f logs/security.log
```

## 📊 Raporty Bezpieczeństwa

Pipeline generuje następujące raporty:

1. **security-summary.md** - Podsumowanie wszystkich skanów
2. **security-report.json** - Szczegółowe wyniki w JSON
3. **Individual tool reports**:
   - `safety-report.json`
   - `bandit-report.json`  
   - `trivy-report.json`
   - `zap-baseline-report.json`

### Przykład Security Summary

```markdown
# 🔒 Security Scan Summary

**Commit:** `abc12345`
**Generated:** 2024-12-06T10:30:00

## 📊 Scan Results

### ✅ SCA Safety
- **Total vulnerabilities:** 0
- **Status:** PASS

### ❌ SAST Bandit  
- **Total issues:** 15
- **High medium issues:** 3
- **Status:** FAIL

### ✅ Container Trivy
- **Total vulnerabilities:** 45
- **High critical:** 0
- **Status:** PASS

## 🚨 Action Required

The following scans found security issues:
- SAST Bandit

**Please review the detailed reports and fix the identified vulnerabilities.**
```

## 🎓 Kryteria Zaliczenia

### ✅ Checklist Projektu

- [ ] Pipeline CI/CD zbudowany zgodnie z DevSecOps
- [ ] Obraz Docker zbudowany i przeskanowany Trivy
- [ ] Obraz wypchnięty do publicznego rejestru
- [ ] SCA: naprawione min. 2-3 podatności HIGH/CRITICAL
- [ ] SAST: naprawione min. 2-3 podatności HIGH/CRITICAL  
- [ ] Secrets: usunięte/przeniesione min. 2-3 znaleziska
- [ ] DAST: naprawione min. 2-3 podatności HIGH/CRITICAL
- [ ] DAST używa tymczasowego deployment w CI
- [ ] Dokumentacja wszystkich napraw

### 📝 Sprawozdanie

Sprawozdanie powinno zawierać:

1. **Opis Pipeline'u**
   - Architektura CI/CD
   - Użyte narzędzia
   - Konfiguracja każdego etapu

2. **Analiza Podatności**
   - Lista znalezionych podatności
   - Klasyfikacja (HIGH/CRITICAL/MEDIUM/LOW)
   - Opis wpływu na bezpieczeństwo

3. **Implementacja Napraw**
   - Szczegółowy opis każdej naprawy
   - Kod przed i po zmianie
   - Uzasadnienie rozwiązania

4. **Wyniki Skanów**
   - Screenshots z raportów
   - Metryki before/after
   - Pozostałe known issues

5. **Wnioski**
   - Lessons learned
   - Rekomendacje dla zespołu
   - Propozycje ulepszeń

## 🚨 Troubleshooting

### Typowe Problemy

**1. Pipeline fails na DAST**
```bash
# Sprawdź czy aplikacja startuje
docker logs pygoat-test

# Zwiększ timeout w workflow
sleep 60  # zamiast 30
```

**2. Trivy nie znajduje podatności**
```bash
# Użyj starszego base image dla więcej podatności
FROM python:3.8-slim  # zamiast 3.9.18-slim-bullseye

# Lub dodaj podatne pakiety systemowe
RUN apt-get update && apt-get install -y \
    openssl=1.1.1d-0+deb10u6 \
    curl=7.64.0-4+deb10u1
```

**3. DAST ZAP timeout**
```bash
# Zwiększ timeout w ZAP scan
--timeout 300  # 5 minut
```

**4. GitHub Actions przekracza limit czasu**
```bash
# Optymalizuj Dockerfile - użyj multi-stage build
# Zmniejsz liczbę skanów w jednym jobie
# Użyj cache dla dependencies
```

## 🔗 Przydatne Linki

- [PyGoat Repository](https://github.com/adeyosemanputra/pygoat)
- [OWASP Vulnerable Apps Directory](https://owasp.org/www-project-vulnerable-web-applications-directory/)
- [Docker-in-Docker GitHub Actions](https://datawookie.dev/blog/2024/04/dind-in-github-actions/)
- [GitLab DinD Documentation](https://docs.gitlab.com/ee/ci/docker/using_docker_build.html)
- [Trivy Documentation](https://github.com/aquasecurity/trivy)
- [OWASP ZAP Docker](https://hub.docker.com/r/owasp/zap2docker-stable/)

## 📚 Dodatkowe Zasoby

### Narzędzia DevSecOps

1. **SCA Tools**
   - [OWASP Dependency Check](https://jeremylong.github.io/DependencyCheck/)
   - [Snyk](https://snyk.io/)
   - [WhiteSource](https://www.mend.io/)

2. **SAST Tools**
   - [SonarQube](https://www.sonarqube.org/)
   - [Checkmarx](https://checkmarx.com/)
   - [Veracode](https://www.veracode.com/)

3. **DAST Tools**
   - [Burp Suite Enterprise](https://portswigger.net/burp/enterprise)
   - [Rapid7 AppSpider](https://www.rapid7.com/products/appspider/)
   - [Netsparker](https://www.netsparker.com/)

### Security Best Practices

1. **Shift-Left Security**
   - Integracja testów bezpieczeństwa w IDE
   - Pre-commit hooks z security checks
   - Security training dla developerów

2. **Continuous Monitoring**
   - Runtime Application Self-Protection (RASP)
   - Security metrics i dashboards
   - Automated incident response

3. **Compliance**
   - GDPR compliance checks
   - SOC 2 requirements
   - ISO 27001 standards

## 🏆 Rozszerzenia Projektu

### Level 2: Advanced DevSecOps

```yaml
# Dodatkowe stages do pipeline
- infrastructure_scanning:  # Terraform/CloudFormation
- license_compliance:       # License violations
- container_runtime:        # Runtime security monitoring
- api_security:            # API-specific tests
- mobile_security:         # If mobile components exist
```

### Level 3: Production-Ready

```yaml
# Production enhancements
- blue_green_deployment:    # Zero-downtime deployment
- canary_releases:         # Gradual rollout
- security_monitoring:     # Real-time alerts
- incident_response:       # Automated response
- compliance_reporting:    # Regulatory reports
```

## 📋 Checklista Pre-Deployment

### Przed wdrożeniem na produkcję:

- [ ] Wszystkie HIGH/CRITICAL podatności naprawione
- [ ] Security headers skonfigurowane
- [ ] HTTPS wymuszony
- [ ] Rate limiting włączony
- [ ] Logging bezpieczeństwa aktywny
- [ ] Backup i disaster recovery plan
- [ ] Security incident response plan
- [ ] Penetration testing wykonany
- [ ] Security review przez zespół

## 🎯 Metryki Sukcesu

### KPIs dla DevSecOps:

1. **Security Metrics**
   - Mean Time to Fix (MTTF) vulnerabilities
   - % of HIGH/CRITICAL vulnerabilities fixed within SLA
   - Number of security issues found in each phase
   - Security debt ratio

2. **Process Metrics**
   - Pipeline success rate
   - Average pipeline execution time
   - Developer productivity impact
   - Security training completion rate

3. **Business Metrics**
   - Security incidents reduction
   - Compliance score improvement
   - Customer trust metrics
   - Cost of security vs. cost of breaches

### Sample Dashboard Metrics

```json
{
  "security_metrics": {
    "vulnerabilities_found": {
      "sca": 12,
      "sast": 8,
      "dast": 5,
      "container": 15
    },
    "vulnerabilities_fixed": {
      "sca": 10,
      "sast": 6,
      "dast": 4,
      "container": 12
    },
    "fix_rate": "82%",
    "mttf": "2.5 days"
  },
  "pipeline_metrics": {
    "success_rate": "94%",
    "avg_duration": "18 minutes",
    "security_stage_duration": "8 minutes"
  }
}
```

## 🎓 Learning Outcomes

Po ukończeniu tego projektu będziesz potrafić:

1. **Konfigurować** kompletny pipeline DevSecOps
2. **Integrować** różne narzędzia bezpieczeństwa
3. **Analizować** wyniki skanów bezpieczeństwa
4. **Naprawiać** typowe podatności aplikacji webowych
5. **Automatyzować** procesy security testing
6. **Monitować** bezpieczeństwo w CI/CD
7. **Dokumentować** security findings i fixes

## 📞 Support

Jeśli napotkasz problemy podczas implementacji:

1. Sprawdź sekcję **Troubleshooting** powyżej
2. Przejrzyj logi GitHub Actions/GitLab CI
3. Sprawdź dokumentację użytych narzędzi
4. Skonsultuj się z zespołem security

---

## 📄 License

Ten projekt jest udostępniony na licencji MIT. Zobacz plik LICENSE dla szczegółów.

## 🤝 Contributing

Contributions są mile widziane! Proszę:

1. Fork repository
2. Utwórz feature branch
3. Commit changes
4. Push do branch
5. Utwórz Pull Request

---

**Autor**: DevSecOps Team  
**Wersja**: 1.0  
**Data ostatniej aktualizacji**: December 2024