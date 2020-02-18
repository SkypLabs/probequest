===========
Development
===========

Running the unit tests
----------------------

`tox`_ is used to run the unit tests:

::

    tox


Releasing a new version
-----------------------

Below are the different steps to do before releasing a new version:

- Run all tests and be sure they all pass
- Update the `VERSION` variable in `probequest/version.py`
- Update the requirements in `setup.py` if needed
- Update the package's metadata (description, classifiers, etc) in `setup.py` if needed
- Update `README.rst` if needed
- Update the documentation if needed and make sure it compiles well (`cd ./docs && make html`)
- Update the copyright year in `docs/conf.py` if needed
- Add the corresponding release note to `CHANGELOG.md`

After having pushed the new release:

- Edit the release note on GitHub

.. _tox: https://tox.readthedocs.io
