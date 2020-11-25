import unittest
import coverage
import os

include = ["vdx_helper/*"]
omitted = ['tests/*', 'vdx_helper/__init__.py']

os.system('coverage erase')
os.system('coverage run tests/_test_runner.py')
os.system('coverage report -m --include={} --omit={}'.format(','.join(include), ','.join(omitted)))
