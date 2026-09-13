# Two stages. The first builds the React bundle with Node; the second is a
# Python image that serves it, so the runtime image carries no Node, no
# node_modules and no build tooling.
FROM node:20-slim AS web

WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build


# The app image. It contains the analyst and its security layers; it does not
# contain a language model. Inference is reached over the network at
# OLLAMA_HOST, so the same image runs against a laptop's Ollama, a shared
# inference host, or nothing at all -- the security tests do not need a model,
# which is what lets CI gate on them.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# CPU-only torch, installed first and from PyTorch's CPU index. Left to itself,
# sentence-transformers pulls the CUDA build and its nvidia-* dependencies --
# over a gigabyte of GPU runtime for an image that will never see a GPU, since
# inference happens in Ollama and this container only computes embeddings.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Dependencies next: they change far less often than the source, so this layer
# survives most rebuilds.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY --from=web /web/dist ./web/dist

# Generate the dataset and load it at build time so the container starts ready.
RUN python scripts/gen_data.py && python -c "import db; db.init_db(rebuild=True)"

# Run as an unprivileged user. The app only ever reads its database, and the
# SQLite connection is opened read-only besides, but defence in depth is the
# whole point of this project.
RUN useradd --create-home --uid 10001 analyst && chown -R analyst:analyst /app
USER analyst

ENV OLLAMA_HOST=http://host.docker.internal:11434

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/models')"

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
