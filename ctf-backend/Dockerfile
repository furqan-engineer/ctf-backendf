FROM python:3.11-slim

# ---- system deps: the CTF "tool belt" ----------------------------------
# binwalk        -> firmware/file carving, embedded file detection
# exiftool       -> metadata extraction (images, pdfs, office docs...)
# steghide       -> classic LSB/jpeg steganography
# foremost       -> file carving from raw/blob data
# unzip/p7zip    -> archive extraction (zip/7z), incl. password-protected probing
# binutils       -> strings, objdump
# xxd            -> hex dump
# tesseract-ocr  -> OCR on images that hide text
# ruby + gems    -> zsteg (PNG/BMP stego), a ruby tool with no good py equivalent
# file           -> magic-byte identification
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    libimage-exiftool-perl \
    steghide \
    foremost \
    unzip \
    p7zip-full \
    binutils \
    xxd \
    tesseract-ocr \
    file \
    ruby \
    ruby-dev \
    build-essential \
    && gem install zsteg --no-document \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# non-root user: the whole point of this service is running tools against
# untrusted uploaded files, so don't do it as root
RUN useradd -m -u 1001 ctfuser && chown -R ctfuser:ctfuser /app
USER ctfuser

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

# Railway injects $PORT; default to 8000 for local `docker run`
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
