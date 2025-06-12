#!/bin/bash

# validate-project.sh
# Skrypt do walidacji kompletności projektu DevSecOps

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
CHECKS_PASSED=0
CHECKS_FAILED=0
TOTAL_CHECKS=0

print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}  PyGoat DevSecOps Project Validation${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
}

print_check() {
    local status=$1
    local message=$2
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ "$status" = "PASS" ]; then
        echo -e "✅ ${GREEN}PASS${NC} - $message"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    elif [ "$status" = "FAIL" ]; then
        echo -e "❌ ${RED}FAIL${NC} - $message"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    elif [ "$status" = "WARN" ]; then
        echo -e "⚠️  ${YELLOW}WARN${NC} - $message"
    else
        echo -e "ℹ️  ${BLUE}INFO${NC} - $message"
    fi
}

check_file_exists() {
    local file=$1
    local description=$2
    
    if [ -f "$file" ]; then
        print_check "PASS" "$description exists: $file"
        return 0
    else
        print_check "FAIL" "$description missing: $file"
        return 1
    fi
}

check_directory_exists() {
    local dir=$1
    local description=$2
    
    if [ -d "$dir" ]; then
        print_check "PASS" "$description exists: $dir"
        return 0
    else
        print_check "FAIL" "$description missing: $dir"
        return 1
    fi
}

check_command_exists() {
    local cmd=$1
    local description=$2
    
    if command -v "$cmd" &> /dev/null; then
        print_check "PASS" "$description available: $cmd"
        return 0
    else
        print_check "WARN" "$description not found: $cmd (install recommended)"
        return 1
    fi
}

validate_workflow_syntax() {
    local workflow_file=".github/workflows/devsecops.yml"
    
    if [ -f "$workflow_file" ]; then
        # Basic YAML syntax check
        if python3 -c "import yaml; yaml.safe_load(open('$workflow_file'))" 2>/dev/null; then
            print_check "PASS" "GitHub workflow YAML syntax is valid"
        else
            print_check "FAIL" "GitHub workflow YAML syntax is invalid"
        fi
        
        # Check for required sections
        if grep -q "SCA\|SAST\|DAST\|secrets\|container" "$workflow_file"; then
            print_check "PASS" "Workflow contains security scanning stages"
        else
            print_check "FAIL" "Workflow missing security scanning stages"
        fi
    fi
}

validate_dockerfile() {
    local dockerfile="Dockerfile"
    
    if [ -f "$dockerfile" ]; then
        # Check for security best practices
        if grep -q "USER.*pygoat\|USER.*[^root]" "$dockerfile"; then
            print_check "PASS" "Dockerfile uses non-root user"
        else
            print_check "FAIL" "Dockerfile runs as root (security risk)"
        fi
        
        if grep -q "HEALTHCHECK" "$dockerfile"; then
            print_check "PASS" "Dockerfile includes health check"
        else
            print_check "WARN" "Dockerfile missing health check"
        fi
        
        if grep -q "slim\|alpine" "$dockerfile"; then
            print_check "PASS" "Dockerfile uses minimal base image"
        else
            print_check "WARN" "Consider using minimal base image (slim/alpine)"
        fi
    fi
}

validate_requirements() {
    local req_file="requirements.txt"
    
    if [ -f "$req_file" ]; then
        # Check for updated Django version
        if grep -q "Django==4\|Django>=4" "$req_file"; then
            print_check "PASS" "Django version is up to date (4.x)"
        else
            print_check "FAIL" "Django version should be updated to 4.x"
        fi
        
        # Check for security packages
        if grep -q "django-security\|django-csp" "$req_file"; then
            print_check "PASS" "Security packages included in requirements"
        else
            print_check "WARN" "Consider adding django-security packages"
        fi
    fi
}

validate_security_configs() {
    echo -e "\n${YELLOW}Checking security configurations...${NC}"
    
    # Bandit config
    if [ -f ".bandit" ] || [ -f "bandit.yml" ]; then
        print_check "PASS" "Bandit configuration file exists"
    else
        print_check "WARN" "Bandit configuration file missing"
    fi
    
    # GitLeaks config
    if [ -f ".gitleaks.toml" ]; then
        print_check "PASS" "GitLeaks configuration file exists"
    else
        print_check "WARN" "GitLeaks configuration file missing"
    fi
    
    # ZAP rules
    if [ -f ".zap/rules.tsv" ]; then
        print_check "PASS" "ZAP rules configuration exists"
    else
        print_check "WARN" "ZAP rules configuration missing"
    fi
}

check_git_setup() {
    echo -e "\n${YELLOW}Checking Git setup...${NC}"
    
    # Check if it's a Git repository
    if [ -d ".git" ]; then
        print_check "PASS" "Git repository initialized"
        
        # Check for GitLab/GitHub remote
        if git remote -v | grep -q "github.com\|gitlab.com"; then
            print_check "PASS" "Git remote configured (GitHub/GitLab)"
        else
            print_check "WARN" "Git remote not configured for GitHub/GitLab"
        fi
        
        # Check .gitignore
        if [ -f ".gitignore" ]; then
            if grep -q "\.env\|security-reports\|logs" ".gitignore"; then
                print_check "PASS" "Gitignore includes security patterns"
            else
                print_check "WARN" "Gitignore missing security patterns"
            fi
        else
            print_check "WARN" "Gitignore file missing"
        fi
    else
        print_check "FAIL" "Not a Git repository"
    fi
}

check_docker_setup() {
    echo -e "\n${YELLOW}Checking Docker setup...${NC}"
    
    check_command_exists "docker" "Docker"
    check_command_exists "docker-compose" "Docker Compose"
    
    # Test Docker functionality
    if command -v docker &> /dev/null; then
        if docker --version &> /dev/null; then
            print_check "PASS" "Docker is functional"
        else
            print_check "FAIL" "Docker is installed but not functional"
        fi
    fi
}

check_python_setup() {
    echo -e "\n${YELLOW}Checking Python setup...${NC}"
    
    check_command_exists "python3" "Python 3"
    check_command_exists "pip" "Pip package manager"
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        if [[ "$PYTHON_VERSION" == 3.9* ]] || [[ "$PYTHON_VERSION" == 3.1* ]]; then
            print_check "PASS" "Python version is suitable: $PYTHON_VERSION"
        else
            print_check "WARN" "Python version is $PYTHON_VERSION (3.9+ recommended)"
        fi
    fi
}

check_security_tools() {
    echo -e "\n${YELLOW}Checking security tools...${NC}"
    
    check_command_exists "bandit" "Bandit SAST tool"
    check_command_exists "safety" "Safety SCA tool"
    check_command_exists "pip-audit" "Pip-audit tool"
    check_command_exists "semgrep" "Semgrep SAST tool"
    check_command_exists "trivy" "Trivy container scanner"
    
    # Check if tools can be installed
    if ! command -v bandit &> /dev/null; then
        print_check "INFO" "Run: pip install bandit safety pip-audit semgrep"
    fi
}

test_application() {
    echo -e "\n${YELLOW}Testing application...${NC}"
    
    # Check if requirements can be installed
    if [ -f "requirements.txt" ]; then
        if python3 -m pip install -r requirements.txt --dry-run &> /dev/null; then
            print_check "PASS" "Requirements.txt is valid"
        else
            print_check "FAIL" "Requirements.txt has issues"
        fi
    fi
    
    # Check if Django app can be validated
    if [ -f "manage.py" ]; then
        if python3 manage.py check --deploy &> /dev/null; then
            print_check "PASS" "Django application passes deployment checks"
        else
            print_check "WARN" "Django deployment checks found issues"
        fi
    fi
    
    # Test Docker build
    if command -v docker &> /dev/null && [ -f "Dockerfile" ]; then
        print_check "INFO" "Testing Docker build (this may take a moment)..."
        if timeout 300 docker build -t pygoat-test . &> /dev/null; then
            print_check "PASS" "Docker image builds successfully"
            docker rmi pygoat-test &> /dev/null || true
        else
            print_check "FAIL" "Docker build failed"
        fi
    fi
}

generate_report() {
    echo -e "\n${BLUE}================================================${NC}"
    echo -e "${BLUE}  Validation Report${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    echo "Total Checks: $TOTAL_CHECKS"
    echo -e "Passed: ${GREEN}$CHECKS_PASSED${NC}"
    echo -e "Failed: ${RED}$CHECKS_FAILED${NC}"
    echo ""
    
    local success_rate=$((CHECKS_PASSED * 100 / TOTAL_CHECKS))
    echo "Success Rate: $success_rate%"
    echo ""
    
    if [ $CHECKS_FAILED -eq 0 ]; then
        echo -e "🎉 ${GREEN}Project validation PASSED!${NC}"
        echo "Your DevSecOps project is ready for submission."
    elif [ $success_rate -ge 80 ]; then
        echo -e "⚠️  ${YELLOW}Project validation PASSED with warnings.${NC}"
        echo "Address the failed checks to improve your project."
    else
        echo -e "❌ ${RED}Project validation FAILED.${NC}"
        echo "Please fix the critical issues before proceeding."
    fi
    
    echo ""
    echo "Next steps:"
    echo "1. Address any failed checks"
    echo "2. Test the CI/CD pipeline"
    echo "3. Document your fixes"
    echo "4. Submit your project"
}

create_checklist() {
    cat > PROJECT_CHECKLIST.md << 'EOF'
# 📋 PyGoat DevSecOps Project Checklist

## ✅ Required Files and Configurations

### CI/CD Pipeline
- [ ] `.github/workflows/devsecops.yml` - GitHub Actions workflow
- [ ] Pipeline includes all security scanning stages (SCA, SAST, Secrets, DAST, Container)
- [ ] Docker-in-Docker configuration for DAST testing

### Docker Configuration  
- [ ] `Dockerfile` - Secure container configuration
- [ ] `docker-compose.yml` - Local development setup
- [ ] Non-root user configuration
- [ ] Minimal base image usage

### Security Configurations
- [ ] `.bandit` - Bandit SAST configuration
- [ ] `.gitleaks.toml` - GitLeaks secrets scanning
- [ ] `.zap/rules.tsv` - OWASP ZAP rules
- [ ] Updated `requirements.txt` with secure package versions

### Scripts and Documentation
- [ ] `scripts/fix-vulnerabilities.sh` - Vulnerability fix script
- [ ] `README.md` - Project documentation
- [ ] Security fix examples and documentation

## 🛡️ Security Requirements

### SCA (Software Composition Analysis)
- [ ] Fixed minimum 2-3 HIGH/CRITICAL vulnerabilities in dependencies
- [ ] Updated Django to version 4.x
- [ ] Updated Pillow and other vulnerable packages

### SAST (Static Application Security Testing)
- [ ] Fixed minimum 2-3 HIGH/CRITICAL code vulnerabilities
- [ ] Removed hardcoded secrets
- [ ] Added security headers configuration

### Secrets Scanning
- [ ] Removed/moved minimum 2-3 HIGH/CRITICAL secret findings
- [ ] Environment variables for sensitive data
- [ ] Updated .gitignore with security patterns

### Container Security
- [ ] Fixed minimum 2-3 HIGH/CRITICAL container vulnerabilities
- [ ] Non-root user in container
- [ ] Minimal base image
- [ ] Package cleanup

### DAST (Dynamic Application Security Testing)
- [ ] Fixed minimum 2-3 HIGH/CRITICAL runtime vulnerabilities
- [ ] Temporary deployment working in CI
- [ ] OWASP ZAP scanning configured

## 🚀 Deployment Requirements

### Docker Registry
- [ ] Image successfully built
- [ ] Image scanned with Trivy
- [ ] Image pushed to public registry (Docker Hub)
- [ ] Security scan results documented

### Documentation
- [ ] All fixes documented with before/after examples
- [ ] Security scan reports included
- [ ] Pipeline execution screenshots
- [ ] Lessons learned and recommendations

## 🎯 Success Criteria

- [ ] All HIGH/CRITICAL vulnerabilities addressed (minimum 2-3 per scan type)
- [ ] Pipeline executes successfully without critical failures
- [ ] Docker image available in public registry
- [ ] Complete documentation of all security improvements
- [ ] DAST testing uses temporary deployment in CI environment

---

**Project Status**: [ ] Ready for Submission

**Notes**: 
- Remember this is an intentionally vulnerable application for learning
- Some vulnerabilities may be left for educational purposes
- Focus on demonstrating DevSecOps principles and toolchain integration
EOF

    print_check "PASS" "Created PROJECT_CHECKLIST.md"
}

# Main execution
main() {
    print_header
    
    echo -e "${YELLOW}Validating project structure...${NC}"
    check_file_exists ".github/workflows/devsecops.yml" "GitHub Actions workflow"
    check_file_exists "Dockerfile" "Docker configuration"
    check_file_exists "docker-compose.yml" "Docker Compose configuration"
    check_file_exists "requirements.txt" "Python requirements"
    check_file_exists "scripts/fix-vulnerabilities.sh" "Vulnerability fix script"
    
    check_directory_exists ".github/workflows" "GitHub workflows directory"
    check_directory_exists "security" "Security configurations directory"
    check_directory_exists "scripts" "Scripts directory"
    
    validate_workflow_syntax
    validate_dockerfile
    validate_requirements
    validate_security_configs
    
    check_git_setup
    check_docker_setup
    check_python_setup
    check_security_tools
    
    if [ "$1" = "--full" ]; then
        test_application
    fi
    
    create_checklist
    generate_report
}

# Parse command line arguments
if [[ "$1" = "--help" || "$1" = "-h" ]]; then
    echo "PyGoat DevSecOps Project Validation Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --full    Run full validation including application tests"
    echo "  --help    Show this help message"
    echo ""
    echo "This script validates your DevSecOps project setup and"
    echo "ensures all required components are properly configured."
    exit 0
fi

# Run main function
main "$@"