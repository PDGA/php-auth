#!/bin/bash

docker-compose run --rm -u $(id -u):$(id -g) php ./vendor/bin/phpunit ./src
