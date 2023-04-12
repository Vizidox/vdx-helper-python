FROM python:3.7.7

COPY . .
RUN python -m pip install --upgrade pip==23.0.1
RUN curl -sSL https://install.python-poetry.org | python3 - --version 1.4.2
ENV PATH=/root/.local/bin:$PATH
RUN poetry config virtualenvs.create false
RUN poetry install -vvv