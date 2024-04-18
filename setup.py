from setuptools import setup, find_packages


with open("README.md", 'r') as f:
    Long_Description = f.read()


setup(
    name = 'Scannort',
    version = '1.1.1',
    author = '@0x00650a',
    description = 'Multi-threaded Scanner for open ports in hosts',
    packages = find_packages(),
    #packages = [''],
    install_requires = [
        # No requirement to install for the moment
    ],
    entry_points = {
        'console_scripts' : [
            'Scannort = src.Scannort:main',
        ],
    },
    package_data = {
        'Scannort' : ['ico/icona.png'],
    },
    long_description = Long_Description,
)

