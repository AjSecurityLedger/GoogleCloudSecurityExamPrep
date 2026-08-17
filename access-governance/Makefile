PY ?= python3
OUT ?= out

.PHONY: help install test iam review privacy ropa all clean

help:
	@echo "make install   Install runtime + dev dependencies"
	@echo "make test      Run the test suite"
	@echo "make iam       IAM least-privilege scan over samples/"
	@echo "make review    Build a user access review campaign over samples/"
	@echo "make privacy   Privacy checks over the sample data inventory"
	@echo "make ropa      Render the record of processing activities"
	@echo "make all       Run every scan, writing reports to $(OUT)/"

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest

iam:
	$(PY) -m agp iam-scan --policy samples/iam-policy.json \
		--config config/governance-policy.yaml --fail-on none

review:
	$(PY) -m agp access-review --policy samples/iam-policy.json \
		--roster samples/roster.csv --config config/governance-policy.yaml \
		--fail-on none

privacy:
	$(PY) -m agp privacy-scan --inventory samples/data-inventory.yaml \
		--config config/governance-policy.yaml --fail-on none

ropa:
	$(PY) -m agp ropa --inventory samples/data-inventory.yaml

all:
	@mkdir -p $(OUT)
	$(PY) -m agp iam-scan --policy samples/iam-policy.json \
		--config config/governance-policy.yaml --out $(OUT)/iam-findings.md --fail-on none
	$(PY) -m agp access-review --policy samples/iam-policy.json \
		--roster samples/roster.csv --config config/governance-policy.yaml \
		--out $(OUT)/access-review.md --csv $(OUT)/access-review.csv --fail-on none
	$(PY) -m agp privacy-scan --inventory samples/data-inventory.yaml \
		--config config/governance-policy.yaml --out $(OUT)/privacy-findings.md --fail-on none
	$(PY) -m agp ropa --inventory samples/data-inventory.yaml --out $(OUT)/ropa.md

clean:
	rm -rf $(OUT) .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
