from setuptools import setup, find_packages, find_namespace_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

# Get the long description from the README file
long_description = (here / 'README.md').read_text(encoding='utf-8')

# Arguments marked as "Required" below must be included for upload to PyPI.
# Fields marked as "Optional" may be commented out.

setup(
    # The name of your package in pip accepted format
    name='cyst-platforms-docker-cryton',
    # The version of your package
    version='0.6.0',
    # The short description of your package
    description='A platform using the Docker emulation for infrastructure creation and Cryton for action execution',
    long_description=long_description,
    long_description_content_type='text/markdown',
    # Any URL with additional information about your package
    url='',
    # Your name and address
    author='',
    author_email='',
    # Update classifiers according to your taste
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Topic :: Scientific/Engineering',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',
        'Topic :: Security',
        'Typing :: Typed',

        # Pick your license as you wish
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate you support Python 3. These classifiers are *not*
        # checked by 'pip install'. See instead 'python_requires' below.
        'Programming Language :: Python :: 3',

        'Operating System :: OS Independent'
    ],
    # If you use the provided directory structure, you should not need to alter this.
    packages=find_packages(exclude=['tests', 'docs']) + find_namespace_packages(include=['cyst_models.*']),
    python_requires='>=3.9, <4',

    # This field lists other packages that your project depends on to run.
    # Any package you put here will be installed by pip when your project is
    # installed, so they must be valid existing projects.
    install_requires=[
        'cyst-core',
        'requests',
        'PyYAML',
        'netaddr'
    ],

    # Add entry points for your package. It should be the instances of package configuration objects.
    # E.g., 'cyst=cyst_models.cyst.main:action_interpreter_description'
    entry_points={
        'cyst.platforms': [
            'docker+cryton=cyst_platforms.docker_cryton.main:platform_description'
        ]
    },

    # List additional URLs that are relevant to your project as a dict.
    #
    # This field corresponds to the "Project-URL" metadata fields:
    # https://packaging.python.org/specifications/core-metadata/#project-url-multiple-use
    #
    # Examples listed include a pattern for specifying where the package tracks
    # issues, where the source is hosted, where to say thanks to the package
    # maintainers, and where to support the project financially. The key is
    # what's used to render the link text on PyPI.
    #project_urls={  # Optional
    #    'Bug Reports': 'https://github.com/pypa/sampleproject/issues',
    #    'Funding': 'https://donate.pypi.org',
    #    'Say Thanks!': 'http://saythanks.io/to/example',
    #    'Source': 'https://github.com/pypa/sampleproject/',
    #},
)
