from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name="clipmate",
    version="0.1.1",
    description="A Python tool for sharing and managing clipboard content over a private local network",
    author="Muhammad Ramzy",
    author_email="mhdramzy777@gmail.com",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/MuhammadRamzy/Cross-platform-clipboard',
    packages=find_packages(),
    install_requires=[
        "pyperclip",
        "termcolor",
        "pyfiglet"
    ],
    entry_points={
        'console_scripts': [
            'clipmate=src.main:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)