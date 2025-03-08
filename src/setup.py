from setuptools import setup, Extension
from Cython.Build import cythonize
import numpy

ext_modules = [
    Extension(
        "sha256_extension",
        sources=["sha256_extension.pyx", "sha256_buffer.c"],  # Beide Dateien einbinden!
        include_dirs=[numpy.get_include(), "."],  # NumPy + aktuelle Verzeichnisse einbinden
        extra_compile_args=["-O3"],  # Optimierung aktivieren
    )
]

setup(
    name="sha256_extension",
    ext_modules=cythonize(ext_modules, language_level="3"),
)
