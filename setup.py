from setuptools import setup, find_packages
setup(
    name='dynamite-sdk-lite',
    version='0.1',
    packages=find_packages(),
    url='http://dynamite.ai',
    license='',
    author='Jamin Becker',
    author_email='jamin@dynamite.ai',
    description='Dynamite SDK is the companion software development kit to Dynamite NSM.',
    install_requires=[
        'elasticsearch>=6.0.0,<7.0.5',
        'pandas==0.25.2',
        'python-dateutil==2.8.0',
        'scipy==0.19.1',
        'scikit_learn==0.19.1',
        'numpy==1.17.2'
    ]
)
