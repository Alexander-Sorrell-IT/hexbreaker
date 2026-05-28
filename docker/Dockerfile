# Hexbreaker — judge try-it-out container (submission artifact #7).
#
# Build:  docker build -t hexbreaker -f docker/Dockerfile .
# Smoke:  docker run --rm -e DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY hexbreaker \
#             generate --seed 4729 --template timestomp --out /tmp/c
# Full case run + score:
#   mkdir -p /tmp/judge-case
#   docker run --rm -e DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY \
#       -v /tmp/judge-case:/case hexbreaker \
#       generate --seed 4729 --template timestomp --out /case
#   docker run --rm -e DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY \
#       -v /tmp/judge-case:/case hexbreaker \
#       run --agent court --case /case --out /case/findings.json
#   docker run --rm -v /tmp/judge-case:/case hexbreaker \
#       score --findings /case/findings.json --answer-key /case/answer_key.json
#
# All Forge cases + Court runs work entirely inside the container. SIFT VM,
# Zimmerman tools, and Anthropic credentials are NOT required.

FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C \
    TZ=UTC \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Forensic CLIs Hexbreaker shells into for the NIST workflow. sleuthkit gives
# us fls/icat/mmls/fsstat; ewf-tools gives ewfmount/ewfverify; yara for
# Layer-6 corroboration. Pinned-base apt footprint ~85MB.
RUN apt-get update && apt-get install -y --no-install-recommends \
        sleuthkit \
        ewf-tools \
        yara \
        ca-certificates \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/hexbreaker

# Install deps first so the Docker layer cache helps on iterative builds.
COPY pyproject.toml /opt/hexbreaker/
COPY src/hexbreaker/__init__.py /opt/hexbreaker/src/hexbreaker/__init__.py
RUN pip install -e .

# Rest of the source.
COPY src/ /opt/hexbreaker/src/
COPY scripts/ /opt/hexbreaker/scripts/
COPY tests/ /opt/hexbreaker/tests/
COPY docs/ /opt/hexbreaker/docs/

# python-registry is needed for scripts/court_on_nist.py (NIST hive parsing).
RUN pip install python-registry pytest

# Smoke-test the install so a broken image fails to build, not at first run.
RUN hexbreaker --help > /dev/null \
    && hexbreaker generate --seed 999 --template timestomp --out /tmp/sanity-case > /dev/null \
    && rm -rf /tmp/sanity-case

ENTRYPOINT ["hexbreaker"]
CMD ["--help"]
