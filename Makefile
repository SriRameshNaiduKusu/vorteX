.PHONY: install dev uninstall clean

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

install:
	@echo "[*] Installing vorteX..."
	@if command -v pipx > /dev/null 2>&1; then \
		echo "[*] pipx found — installing via pipx..."; \
		pipx install .; \
	else \
		echo "[*] pipx not found — creating virtual environment at $(VENV)/..."; \
		python3 -m venv $(VENV); \
		$(PIP) install --upgrade pip; \
		$(PIP) install .; \
		echo ""; \
		echo "[✔] Installation complete."; \
		echo "    Activate with: source $(VENV)/bin/activate"; \
		echo "    Then run: vorteX -h"; \
	fi

dev:
	@echo "[*] Setting up development environment in $(VENV)/..."
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"
	@echo "[✔] Dev environment ready. Activate with: source $(VENV)/bin/activate"

uninstall:
	@echo "[*] Uninstalling vorteX..."
	@if command -v pipx > /dev/null 2>&1 && pipx list 2>/dev/null | grep -q vortex-recon; then \
		pipx uninstall vortex-recon; \
	fi
	@if [ -d "$(VENV)" ]; then \
		echo "[*] Removing virtual environment $(VENV)/..."; \
		rm -rf $(VENV); \
	fi
	@echo "[✔] Uninstall complete."

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -rf build/ dist/ *.egg-info/ .eggs/
	find . -type d -name __pycache__ -not -path './.git/*' | xargs rm -rf
	find . -name "*.pyc" -not -path './.git/*' -delete
	find . -name "*.pyo" -not -path './.git/*' -delete
	find . -name ".pytest_cache" -not -path './.git/*' | xargs rm -rf
	find . -name ".ruff_cache" -not -path './.git/*' | xargs rm -rf
	@echo "[✔] Clean complete."
