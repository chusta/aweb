.PHONY: build clean install uninstall setup setup-dev test


build: clean
	python3 setup.py --quiet sdist
	sha256sum dist/* > dist/sha256sum.txt

clean:
	rm -rf .coverage cover ws.egg-info build dist
	find . -name __pycache__ | xargs rm -rf

install:
	pip3 install dist/ws-*.tar.gz

uninstall:
	pip3 uninstall -y ws

setup:
	pip3 install -r req.txt

setup-dev: setup
	pip3 install -r req-dev.txt

test:
	nosetests --cover-package=aweb --with-coverage --cover-erase --cover-html
