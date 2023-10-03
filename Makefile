
rundocker := docker run --rm -v "$$(pwd):/home/user/src" jamesob/verystable
rundockerit := docker run -it --rm -v "$$(pwd):/home/user/src" jamesob/verystable

build: 
	docker build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) -t jamesob/verystable -f test.Dockerfile .

test: 
	$(rundocker) pytest verystable
	$(rundocker) ruff verystable

shell: 
	$(rundockerit) bash


ipy:
	$(rundockerit) ipython
