SHELL := /bin/bash

# go install github.com/divan/expvarmon@latest

run:
	go run app/sales-api/main.go

tidy:
	go mod tidy
	go mod vendor