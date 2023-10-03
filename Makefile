
ifeq ($(origin ON_GITHUB), undefined)
	DOCKER_FLAGS := -it
else
	DOCKER_FLAGS :=
endif

rundocker := docker run $(DOCKER_FLAGS) --rm -v "$$(pwd):/home/user/src" jamesob/verystable:test

docker-pull:
	docker pull docker.io/jamesob/verystable:test

build: 
	docker build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) -t jamesob/verystable:test -f test.Dockerfile .

test: 
	$(rundocker) pytest verystable
	$(rundocker) ruff verystable
	$(rundocker) mypy verystable

shell: 
	$(rundocker) bash


ipy:
	$(rundocker) ipython
