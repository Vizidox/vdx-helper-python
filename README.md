# VDX Helper
This repository provides a wrapper for every call made to VDX Core Api.

## How it works
This helper first needs to be authorized by wielding valid token from Keycloak, then use that token for further requests as long as it has not expired.

Each method also allows one to include their own custom mappers, enabling the method to return the result in the format the user wishes.
![workflow illustration](docs/images/vdx-helper.png)

## Prerequisites

- Python Poetry
- Docker + Docker-compose

## Usage

### Initialization

Required parameters: 
- api_url: The url leading to Core API server
- auth_url: The url leading to authentication server
- client_secret: client secret
- client_id: client id


```
vdx_helper = VDXHelper(api_url='https://vizidox-core-api.com', auth_url='https://auth.com', client_secret=secret, client_id=client_id)
```

### Mapper example
A mapper will receive a json-formatted parameter as their input. The following example mapper will add a field

```
def example_mapper(json_file):
    returned_json = copy.deepcopy(json_file)
    returned_json['additional_field'] = 'additional_value'
    return returned_json
```

### Usage example

```
vdx_helper.upload_file(file=the_file_to_upload, mapper=example_mapper)
```

## Running the tests

You can run the tests with poetry if you like. You can also obtain the code coverage.

```
poetry run pytest --cov=vdx_helper
```

### Run the test locally with docker-compose step-by-step
1. Turn up the docker-containers
```
docker-compose up -d
```

2. Run the tests via the vdx-helper docker container
```
docker-compose run vdx-helper pytest tests
```


## Documentation

To build the documentation locally:

```shell
cd docs
make html
```

The build files can be found in docs/build. Open the generated index.html file in the html folder, and you can now 
navigate the documentation. Repeat the above command and refresh your browser every time you update the documentation.
All source files are in docs/source, with vdx_helper containing the documentation generated from docstrings.
 
## Authors

* **Tiago Santos** - *Initial work* - [Vizidox](https://vizidox.com)
* **Joana Teixeira** - *Corrections and improvements* - [Vizidox](https://vizidox.com)
* **Rita Mariquitos** - *Corrections and improvements* - [Vizidox](https://vizidox.com)

## License

All of the code developed in this project belongs to Vizidox Solutions Limited under the ownership of Freddy Elturk and 
any distribution or use must be authorized and agreed upon previously.
