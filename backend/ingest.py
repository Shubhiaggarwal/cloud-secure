"""
ingest.py

Run once (and any time knowledge/*.md changes) to build the RAG knowledge
base used by the always-available chatbot's search_security_knowledge tool.

Run from the backend/ directory:
    python ingest.py
"""

import os
import sys

from app import config
from app.ai import rag

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DOCUMENTS = [
    ("app/knowledge/aws/s3_security.md", "S3", "s3_security"),
    ("app/knowledge/aws/iam_security.md", "IAM", "iam_security"),
    ("app/knowledge/aws/ec2_security.md", "EC2", "ec2_security"),
    ("app/knowledge/aws/security_groups.md", "EC2", "security_groups"),
    ("app/knowledge/aws/cloudtrail_security.md", "CloudTrail", "cloudtrail_security"),
    ("app/knowledge/cis/aws_foundations.md", "CIS", "cis_aws_foundations"),
    ("app/knowledge/cspm/scanner_rules.md", "CSPM", "scanner_rules"),
    ("app/knowledge/cspm/remediation_guides.md", "CSPM", "remediation_guides"),
]


def main():
    if not config.has_gemini_key():
        print("[!] GEMINI_API_KEY is not set. Set it in your .env file before running ingestion.")
        sys.exit(1)

    total_chunks = 0
    for relative_path, service, topic in DOCUMENTS:
        full_path = os.path.join(BASE_DIR, relative_path)
        if not os.path.exists(full_path):
            print(f"[!] Skipping missing file: {relative_path}")
            continue
        try:
            count = rag.ingest_document(full_path, metadata={"service": service, "topic": topic})
        except Exception as e:
            print(f"[!] Failed to ingest {relative_path}: {e}")
            continue
        print(f"[+] Ingested {relative_path}: {count} chunk(s)")
        total_chunks += count

    print(f"\nDone. {total_chunks} total chunks stored in Chroma "
          f"collection '{config.CHROMA_COLLECTION_NAME}' at '{config.CHROMA_PERSIST_DIR}'.")


if __name__ == "__main__":
    main()
