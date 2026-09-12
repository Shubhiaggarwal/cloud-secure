"""
app/ai/rag.py

Retrieval-Augmented Generation over a small, curated cybersecurity
knowledge base (AWS docs summaries, CIS AWS Foundations Benchmark, and this
project's own CSPM rules/remediation guidance).

Pipeline:
    knowledge/*.md -> chunk -> Gemini embeddings
        -> a small local vector store (JSON + NumPy cosine similarity)
        -> semantic similarity search -> relevant chunks handed to the LLM

Note on the vector store: this originally used Chroma, but Chroma's
dependency chroma-hnswlib is a C++ extension with no prebuilt wheel for
every Python/OS combination (notably recent Python on Windows), which
forces a local compile requiring Visual Studio Build Tools. For a knowledge
base this size (a few dozen short chunks), a full ANN index is unnecessary
anyway - a flat NumPy cosine-similarity search over all vectors is
effectively instant and has zero native build requirements. The public
interface (ingest_document, query, is_ready) is unchanged, so nothing else
in the backend (chat_service, routers) needs to change.

This module does NOT train or fine-tune anything - it only retrieves
existing text so the LLM can ground its answers in it.
"""

import hashlib
import json
import os

from app import config

_genai_client = None
_store_cache = None


def _get_genai_client():
    global _genai_client
    if _genai_client is None:
        from google import genai
        _genai_client = genai.Client(api_key=config.GEMINI_API_KEY)
    return _genai_client


def _store_path():
    """The vector store is a single JSON file inside CHROMA_PERSIST_DIR,
    named after the collection, so config vars stay meaningful/unchanged."""
    return os.path.join(config.CHROMA_PERSIST_DIR, f"{config.CHROMA_COLLECTION_NAME}.json")


def _load_store():
    global _store_cache
    if _store_cache is not None:
        return _store_cache

    path = _store_path()
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            _store_cache = json.load(f)
    else:
        _store_cache = {"records": {}}  # id -> {embedding, document, metadata}
    return _store_cache


def _save_store(store):
    os.makedirs(config.CHROMA_PERSIST_DIR, exist_ok=True)
    with open(_store_path(), "w", encoding="utf-8") as f:
        json.dump(store, f)


def embed_text(text):
    """Returns an embedding vector for the given text via Gemini's
    embedding model (config.GEMINI_EMBEDDING_MODEL)."""
    client = _get_genai_client()
    response = client.models.embed_content(
        model=config.GEMINI_EMBEDDING_MODEL,
        contents=text,
    )
    return response.embeddings[0].values


def _chunk_id(source, chunk_text):
    """Deterministic id so re-running ingestion is idempotent (upsert, not duplicate)."""
    digest = hashlib.sha256(f"{source}:{chunk_text}".encode("utf-8")).hexdigest()[:16]
    return f"{source}:{digest}"


def chunk_markdown(text, max_chars=1200):
    """
    Simple, dependency-free chunking: splits on markdown headings first,
    then further splits any oversized section by paragraph. Good enough for
    a knowledge base of short, well-structured security documents.
    """
    sections = []
    current = []
    for line in text.splitlines():
        if line.startswith("#") and current:
            sections.append("\n".join(current).strip())
            current = [line]
        else:
            current.append(line)
    if current:
        sections.append("\n".join(current).strip())

    chunks = []
    for section in sections:
        if not section:
            continue
        if len(section) <= max_chars:
            chunks.append(section)
            continue
        paragraph_buffer = ""
        for paragraph in section.split("\n\n"):
            if len(paragraph_buffer) + len(paragraph) > max_chars and paragraph_buffer:
                chunks.append(paragraph_buffer.strip())
                paragraph_buffer = paragraph
            else:
                paragraph_buffer += "\n\n" + paragraph
        if paragraph_buffer.strip():
            chunks.append(paragraph_buffer.strip())

    return [c for c in chunks if c.strip()]


def ingest_document(filepath, metadata):
    """
    Chunks a single markdown file, embeds each chunk, and upserts it into
    the local vector store. Safe to re-run: chunk ids are content-hash
    based, so re-ingesting unchanged content is a no-op overwrite, not a
    duplicate.
    """
    store = _load_store()

    with open(filepath, "r", encoding="utf-8") as f:
        text = f.read()

    chunks = chunk_markdown(text)
    if not chunks:
        return 0

    for chunk in chunks:
        chunk_id = _chunk_id(filepath, chunk)
        store["records"][chunk_id] = {
            "embedding": embed_text(chunk),
            "document": chunk,
            "metadata": {**metadata, "source": filepath},
        }

    _save_store(store)
    return len(chunks)


def _cosine_similarity(a, b):
    import numpy as np
    a = np.array(a)
    b = np.array(b)
    denom = (np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)


def query(query_text, n_results=3):
    """
    Embeds the query and returns the top-n most semantically similar chunks
    from the knowledge base, each with its source metadata.
    """
    store = _load_store()
    records = store.get("records", {})
    if not records:
        return []

    query_embedding = embed_text(query_text)

    scored = [
        (
            _cosine_similarity(query_embedding, record["embedding"]),
            record["document"],
            record["metadata"],
        )
        for record in records.values()
    ]
    scored.sort(key=lambda x: x[0], reverse=True)

    return [
        {"text": doc, "metadata": meta}
        for _score, doc, meta in scored[:n_results]
    ]


def is_ready():
    """Whether the knowledge base has been ingested (store is non-empty)."""
    try:
        store = _load_store()
        return len(store.get("records", {})) > 0
    except Exception:
        return False
