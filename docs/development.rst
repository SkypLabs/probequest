Development
-----------

Running the unit tests
^^^^^^^^^^^^^^^^^^

To run the unit tests:

::

    python3 setup.py test


Releasing a new version
^^^^^^^^^^^^^^^^^^^^^^^

Below are the different steps to do before releasing a new version:

- Run all tests and be sure they all pass
- Update the `VERSION` variable in `setup.py`
- Update the package's metadata (description, classifiers, etc) in `setup.py` if needed
- Update the requirements in `setup.py` and `requirements.txt`
- Update `README.rst` if needed

After having pushed the new release:

- Edit the release note on GitHub
