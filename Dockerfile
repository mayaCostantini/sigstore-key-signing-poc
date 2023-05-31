FROM python:3.10.11-buster

WORKDIR /app

COPY . .

RUN python3 -m pip install -r requirements.txt .
