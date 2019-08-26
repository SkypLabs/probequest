## v0.7.2 - Aug 26, 2019

### Improvements

* Use the new [Scapy built-in asynchronous sniffer](https://scapy.readthedocs.io/en/latest/usage.html#asynchronous-sniffing)
* Introduce the new `Config` object containing the configuration of ProbeQuest

### Fixes

* Fix all linting and style errors

### Misc.

* Drop support for Python 3.3

## v0.7.1 - Mar 6, 2019

### Fixes

* Error when trying to decode ESSIDs using invalid UTF-8 characters ([#4](https://github.com/SkypLabs/probequest/issues/4))
* Arguments not working (-e, -r) ([#17](https://github.com/SkypLabs/probequest/issues/17))

## v0.7.0 - Oct 8, 2018

### Features

* Add the `--fake` option to display fake Wi-Fi EDDISs for development purposes

### Fixes

* Add unit tests following [#5](https://github.com/SkypLabs/probequest/issues/5)

## v0.6.2 - Jul 31, 2018

### Fixes

* Test if a packet has a `Dot11ProbeReq` layer before parsing it ([#5](https://github.com/SkypLabs/probequest/issues/5), [#8](https://github.com/SkypLabs/probequest/issues/8))

## v0.6.1 - May 28, 2018

### Features

* Change the short description in `setup.py`

### Documentation

* Update the installation documentation

### Fixes

* Fix a missing dependency

## v0.6.0 - May 27, 2018

The project has been renamed to ProbeQuest.

### Features

* Refactor the software architecture
* Add a TUI

### Documentation

* Use Sphinx for the documentation

## v0.5.1 - Feb 18, 2018

### Features

* Improve the debug mode

### Fixes

* The sniffer stops after having received the first frame ([#3](https://github.com/SkypLabs/probequest/issues/3))

## v0.5.0 - Feb 7, 2018

### Features

* Refactor the software architecture
* Add the `--ignore-case` argument
* Add a mutual exclusion for the `--exclude` and `--station` arguments
* Add a debug mode
* Display the timestamp as a readable time
* Add unit tests

## v0.4.0 - Sep 19, 2017

### Features

* Display MAC address's OUI if available

## v0.3.0 - Sep 10, 2017

### Features

* Add regex filtering

### Infrastructure

* Deploy automatically the new releases to PyPI using Travis CI

## v0.2.0 - Sep 10, 2017

### Features

* Add station filtering
* Add ESSID filtering
* Add exclusion filtering

## v0.1.0 - Sep 10, 2017

First pre-release.
