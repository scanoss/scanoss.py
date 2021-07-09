
clean:
	@rm -rf dist/* build/* venv/bin/scanoss-py src/scanoss.egg-info

dist: clean dev_uninstall
	python3 setup.py sdist bdist_wheel
	twine check dist/*

dev_setup:
	python3 setup.py develop --user

dev_uninstall:
	python3 setup.py develop --user --uninstall
	@rm -f venv/bin/scanoss-py
	@rm -rf src/scanoss.egg-info

publish_test:
	twine upload --repository testpypi dist/*

publish:
	twine upload dist/*