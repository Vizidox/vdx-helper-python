FROM python:3.6.6

WORKDIR home/app

COPY . home/app

ENV PYTHONPATH /home/app

RUN pip install poetry
RUN poetry config virtualenvs.create false
RUN cd home/app && poetry install
