from setuptools import setup, find_packages
import os

path = os.path.abspath(os.path.dirname(__file__))


def read(filename):
    with open(os.path.join(path, filename), encoding='utf-8') as f:
        return f.read()


setup(
    name='uosrzidmgr',
    author='Lars Kiesow <lars.kiesow@uni-osnabrueck.de>',
    license='GPLv3+',
    version='0.0',
    packages=find_packages(),
    install_requires=read('requirements.txt').split(),
    include_package_data=True,
    long_description=read('README.md'),
    long_description_content_type='text/markdown'
)
