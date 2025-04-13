from setuptools import setup, find_packages

setup(
    name='vortex-recon',
    version='1.0.0',
    author='Sri Ramesh Naidu Kusu',
    description='vorteX - Advanced Async Reconnaissance & Fuzzing Tool',
    packages=find_packages(),
    py_modules=['main'],
    install_requires=[
        'requests',
        'aiohttp',
        'aiodns',
        'tqdm',
        'beautifulsoup4',
        'pyfiglet',
        'colorama'
    ],
    entry_points={
        'console_scripts': [
            'vortex = main:main'
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)
