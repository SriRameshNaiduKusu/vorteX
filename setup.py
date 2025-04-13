from setuptools import setup, find_packages

setup(
    name="vorteX",
    version="1.0.0",
    author="Sri Ramesh Naidu",
    description="An Advanced Asynchronous Reconnaissance Tool for Bug Bounty and Penetration Testing.",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url="https://github.com/SriRameshNaiduKusu/vorteX",
    packages=find_packages(),
    install_requires=[
        "aiohttp",
        "aiodns",
        "requests",
        "tqdm",
        "beautifulsoup4",
        "colorama",
        "pyfiglet"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Intended Audience :: Security Professionals",
    ],
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'vortex = main:main',
        ],
    },
)
