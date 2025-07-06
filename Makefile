VENV_DIR=../venv_mpl
PYTHON=$(VENV_DIR)/bin/python
PIP=$(VENV_DIR)/bin/pip

.PHONY: help venv install freeze clean run

help:
	@echo "Comandi disponibili:"
	@echo "  make venv      - Crea un ambiente virtuale in $(VENV_DIR)"
	@echo "  make install   - Installa le dipendenze da requirements.txt"
	@echo "  make run       - Esegue il file main.py usando l'ambiente virtuale"

venv:
	python3 -m venv $(VENV_DIR)
	@echo "Per attivare: source $(VENV_DIR)/bin/activate"

install:
	$(PIP) install -r requirements.txt

run:
	$(PYTHON) main.py