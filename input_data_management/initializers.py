# services.py
import os
from sentence_transformers import SentenceTransformer
from langchain.text_splitter import RecursiveCharacterTextSplitter
from pinecone import Pinecone, ServerlessSpec
from django.core.exceptions import ImproperlyConfigured

if not os.getenv("PINECONE_API_KEY"):
    raise ImproperlyConfigured("Missing PINECONE_API_KEY")

# Shared sentence transformer
embeddings = SentenceTransformer('all-MiniLM-L6-v2')

# Shared text splitter
text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=150)

# Shared Pinecone index
pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))
index_name = "meeting-transcripts"
if index_name not in pc.list_indexes().names():
    pc.create_index(
        name=index_name,
        dimension=384,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region="us-east-1")
    )
pinecone_index = pc.Index(index_name)
