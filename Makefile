USERID = $(shell id -u)
DOCKER_COMPOSE = USERID=$(USERID) docker compose

.PHONY: install
install:
	uv sync --all-extras

.PHONY: build
build: ## Build the stack
	$(DOCKER_COMPOSE) build

.PHONY: up
up: down ## Bring up the stack
	$(DOCKER_COMPOSE) up -d

.PHONY: down
down: ## Bring down the stack
	$(DOCKER_COMPOSE) down --remove-orphans
