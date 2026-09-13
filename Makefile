.PHONY: setup build test

setup:
	bash setup.sh

build: setup

test:
	pytest
