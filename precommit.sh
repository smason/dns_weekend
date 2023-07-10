SRC=dns_weekend.py

set -euxo pipefail

isort --profile=black $SRC
black $SRC
mypy --strict $SRC
