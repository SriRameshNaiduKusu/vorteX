from setuptools import setup, find_packages

setup(
    name='vortex-recon',
    version='1.0.1',
    author='SriRameshNaidu Kusu',
    description='vorteX - Advanced Async Reconnaissance & Fuzzing Tool',
    packages=find_packages(),
    include_package_data=True,
    install_requires=open('requirements.txt').read().splitlines(),
    entry_points={
        'console_scripts': [
            'vorteX = vortex.main:main',
        ],
    },
)


