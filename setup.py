import setuptools 


try:
    with open('README.rst') as f:
        long_description = f.read()
except IOError:
    long_description = ""
try:
    with open("'requirements.txt'") as f:
        requirements = [x for x in [y.strip() for y in f.readlines()] if x]
except IOError:
    requirements = []


setuptools.setup(
    name='LDSAPI',
    license='GPL',
    author='Joseph Ramsay',
    author_email='jramsay@linz.govt.nz',
    install_requires=requirements,
    version='0.0.1',
    packages=setuptools.find_packages(),
    description='LDS API Utilities Package',
    long_description=long_description
)
