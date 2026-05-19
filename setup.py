from setuptools import find_packages, setup


setup(
    name="ev-ids-sentinel",
    version="0.4.0",
    description="EV-IDS Sentinel: Electric Vehicle IDS feature extraction and live traffic dashboard",
    packages=find_packages(include=["ev_ids_sentinel", "ev_ids_sentinel.*"]),
    install_requires=[
        "dpkt>=1.9.8",
        "scapy>=2.5.0",
        "transformers>=4.41.0",
        "torch>=2.1.0",
        "PySide6>=6.7.0",
    ],
    entry_points={
        "console_scripts": [
            "ev-ids-sentinel=ev_ids_sentinel.cli:main",
            "ev-ids-sentinel-gui=ev_ids_sentinel.gui:main",
        ]
    },
)
