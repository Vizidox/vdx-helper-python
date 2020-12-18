FROM python:3.7.7

COPY . .

ENV PATH=/root/.poetry/bin:$PATH

RUN pip install poetry
RUN poetry config virtualenvs.create false
RUN poetry install -vvv