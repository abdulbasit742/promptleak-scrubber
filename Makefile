test:
	python -m unittest discover -s tests -v

audit:
	python scripts/curated_secret_check.py
