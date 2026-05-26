# Hexbreaker — judge try-it-out container
# Submission artifact #7: `docker run -v $(pwd)/case:/case hexbreaker run-all`
#
# Status: STUB. Final Dockerfile lands Week 3 (Thu 6/12).

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C \
    TZ=UTC \
    PYTHONUNBUFFERED=1

# Forensic CLIs that Hexbreaker shells into.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 python3.11-venv python3-pip \
    sleuthkit \
    yara \
    bulk-extractor \
    ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

# EZ Tools (MFTECmd, AmcacheParser, PECmd, EvtxECmd, RECmd) — pinned via dotnet.
# Volatility 3, Plaso, python-evtx via pip.
# Pinning + verification lands Week 3.

WORKDIR /opt/hexbreaker
COPY . /opt/hexbreaker
RUN python3.11 -m pip install --no-cache-dir -e .

ENTRYPOINT ["hexbreaker"]
CMD ["--help"]
