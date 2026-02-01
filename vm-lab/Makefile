# ==============================================================================
# Red Hat Academy VM Lab - Makefile
# ==============================================================================

.PHONY: help setup keys network build up down logs clean test

# Default target
help:
	@echo "Red Hat Academy VM Lab - Available Commands"
	@echo "============================================"
	@echo ""
	@echo "Setup:"
	@echo "  make setup     - Run full initial setup"
	@echo "  make keys      - Generate encryption keys"
	@echo "  make network   - Create libvirt network"
	@echo ""
	@echo "Docker:"
	@echo "  make build     - Build Docker images"
	@echo "  make up        - Start all services"
	@echo "  make down      - Stop all services"
	@echo "  make restart   - Restart all services"
	@echo "  make logs      - View logs (follow mode)"
	@echo ""
	@echo "Maintenance:"
	@echo "  make status    - Show service status"
	@echo "  make stats     - Show VM statistics"
	@echo "  make clean     - Remove stopped containers and images"
	@echo "  make clean-all - Remove everything including volumes"
	@echo ""
	@echo "Development:"
	@echo "  make test      - Run health checks"
	@echo "  make shell-lti - Shell into LTI server"
	@echo "  make shell-api - Shell into API server"
	@echo ""

# Initial setup
setup: keys network
	@echo "Setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Copy .env.example to .env and configure"
	@echo "2. Prepare your base QCOW2 image"
	@echo "3. Configure Cloudflare Tunnel"
	@echo "4. Run 'make build && make up'"

# Generate keys
keys:
	@echo "Generating keys..."
	@chmod +x scripts/generate-keys.sh
	@./scripts/generate-keys.sh

# Setup libvirt network
network:
	@echo "Setting up libvirt network..."
	@chmod +x scripts/setup-libvirt-network.sh
	@sudo ./scripts/setup-libvirt-network.sh

# Build Docker images
build:
	docker-compose build

# Start services
up:
	docker-compose up -d

# Stop services
down:
	docker-compose down

# Restart services
restart:
	docker-compose restart

# View logs
logs:
	docker-compose logs -f

# View logs for specific service
logs-lti:
	docker-compose logs -f lti-server

logs-api:
	docker-compose logs -f lab-api

# Show status
status:
	@echo "Container Status:"
	@docker-compose ps
	@echo ""
	@echo "Libvirt VMs:"
	@virsh list --all 2>/dev/null || echo "  (libvirt not available)"
	@echo ""
	@echo "ttyd Containers:"
	@docker ps --filter "name=ttyd-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "  (none running)"

# Show statistics
stats:
	@curl -s http://localhost:8000/api/stats 2>/dev/null | python3 -m json.tool || echo "API not available"

# Health check
test:
	@echo "Testing LTI Server..."
	@curl -s http://localhost:8000/lti/health | python3 -m json.tool || echo "FAIL"
	@echo ""
	@echo "Testing API Server..."
	@curl -s http://localhost:8000/health | python3 -m json.tool || echo "FAIL"

# Shell into containers
shell-lti:
	docker-compose exec lti-server /bin/bash

shell-api:
	docker-compose exec lab-api /bin/bash

shell-db:
	docker-compose exec postgres psql -U postgres

# Clean up
clean:
	docker-compose down --remove-orphans
	docker container prune -f
	docker image prune -f

clean-all:
	docker-compose down -v --remove-orphans
	docker system prune -af

# Database commands
db-shell:
	docker-compose exec postgres psql -U postgres -d lab

db-backup:
	@mkdir -p backups
	docker-compose exec postgres pg_dumpall -U postgres > backups/backup-$$(date +%Y%m%d-%H%M%S).sql
	@echo "Backup saved to backups/"

# Development helpers
dev-up:
	docker-compose up

lint:
	@echo "Linting Python files..."
	@docker run --rm -v $$(pwd):/app -w /app python:3.11-slim pip install flake8 && flake8 api/ lti/
