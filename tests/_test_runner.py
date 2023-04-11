import unittest

# load test with test suites
test_suites = unittest.TestLoader().discover('/home/app/tests', pattern='test_*.py')
test_runner = unittest.runner.TextTestRunner()

# start testing
result = test_runner.run(test_suites)

