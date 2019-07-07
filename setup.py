import setuptools


setuptools.setup(
    name = "aweb",
    version = "1.0.0",
    description = "tiny async web server",
    packages = [ "aweb" ],
    install_requires = [
        "pyopenssl",
        "python-magic"
    ],
    entry_points = {
        "console_scripts": [ "aweb=aweb.aweb:main" ]
    }
)
