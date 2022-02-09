# Build
FROM python:3.7.7 as build

COPY . .
ENV PATH=/root/.poetry/bin:$PATH

RUN pip install poetry
RUN poetry config virtualenvs.create false
RUN poetry install -vvv

WORKDIR /docs

RUN make html

# Deploy
FROM nginx:alpine
COPY --from=build /docs/build/html /usr/share/nginx/html
COPY conf/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]