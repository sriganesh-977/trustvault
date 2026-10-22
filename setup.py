from setuptools import setup
from setuptools.command.build_py import build_py
import subprocess, os

class BuildHook(build_py):
    def run(self):
        print("Running npm ci for TrustVault...")
        subprocess.run(["npm", "ci"], check=False)
        super().run()

setup(
    name="trustvault",
    version="0.1.0",
    cmdclass={"build_py": BuildHook},
)
