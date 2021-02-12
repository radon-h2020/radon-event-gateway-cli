# RADON Event Gateway CLI
This CLI application helps you to make a function for passing the event/data between two different providers.

## Table of Contents
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Instructions](#instructions)

## Prerequisites
`event-gateway-cli` requires python 3 and a virtual environment. In a typical modern Linux environment, we should 
already be set. In Ubuntu, however, we might need to run the following commands:

```console
$ sudo apt update
$ sudo apt install -y python3-venv python3-wheel python-wheel-common
```

## Installation
The simplest way to install `event-gateway-cli` is to clone this repository and install the package into virtual 
environment:

```console
$ git clone git@github.com:radon-h2020/radon-event-gateway-cli.git
$ cd radon-event-gateway-cli
radon-event-gateway-cli$ python3 -m venv .venv && . .venv/bin/activate
(.venv) radon-event-gateway-cli$ pip install .
(.venv) radon-event-gateway-cli$ event-gateway-cli -h
usage: event-gateway-cli [-h] {configure-aws,configure-azure} ...

positional arguments:
  {configure-aws,configure-azure}
    configure-aws       Configure credentials for user and service
                        applications.
    configure-azure     Configure credentials for user and service
                        applications.

optional arguments:
  -h, --help            show this help message and exit
```

## Instructions
The user has to configure the access information before using the event gateway.

```
Service is hosted on: 
 1. Different account 
 2. User account
Select an option (1 or 2):2
User account username:
User account password:
```

Next user can configure the event gateway between his already existing microservices. If any parameter is unclear
the user can input `h` character and the client will print more information.

```
Source provider: AWS
Source microservice: S3

Destination provider: Azure
Destination microservice: Azure functions
 ```

Next the client will ask for more information about the start and end point of the gateway.
