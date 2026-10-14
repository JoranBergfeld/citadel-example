# Local stack smoke baseline, not one of the five deployed applications.
FROM scratch AS wheelhouse

FROM --platform=linux/amd64 docker.io/library/python:3.12.15-slim-bookworm@sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

COPY requirements.lock ./
ARG OFFLINE=false
RUN --mount=type=bind,from=wheelhouse,target=/wheelhouse,ro \
    case "$OFFLINE" in \
      false) python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements.lock ;; \
      true) python -m pip install --no-cache-dir --only-binary=:all: --require-hashes --no-index --find-links=/wheelhouse -r requirements.lock ;; \
      *) echo "OFFLINE must be true or false" >&2; exit 2 ;; \
    esac

COPY src/citadel/__init__.py ./citadel/__init__.py
COPY tests/stack ./tests/stack
USER 65532:65532
CMD ["python", "-m", "unittest", "discover", "-s", "tests/stack", "-v"]
