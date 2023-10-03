

build: 
	docker build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) -t jamesob/verystable -f test.Dockerfile .

test: 
	docker run --rm -v "$$(pwd):/src:ro" jamesob/verystable pytest
