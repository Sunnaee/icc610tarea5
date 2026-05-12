"""
Análisis de publicación de secrets en repositorios de GitHub utilizando Gitleaks.

Proceso: 
1. Descubre todos los repositorios públicos de GitHub utilizando la API de GitHub.
2. Ejecuta las consultas de Gitleaks en cada repositorio para identificar posibles secretos expuestos.
3. Almacena los resultados en un formato JSON en data/results

Requesitos:
- Python 3.x
- Gitleaks instalado y accesible desde la línea de comandos

"""

from __future__ import annotations

import json
import subprocess
import os
from pathlib import Path
import logging
import re


if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)s | %(message)s')

LOGGER = logging.getLogger(__name__)
PATRON_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class GitLeaksAnalyzer:
    def __init__(self, repos_path: str, results_path: str):
        self.repos_path = Path(repos_path).expanduser().resolve()
        self.results_path = Path(results_path).expanduser().resolve()
        self.project_root = Path(__file__).parent.parent

    def discover_repositorioes(self) -> list[str]:

        repositorios = sorted(
            str(ruta.relative_to(self.project_root))
            for ruta in self.repos_path.iterdir()
            if ruta.is_dir()
        )

        if not repositorios:
            LOGGER.warning(
                "No se encontraron repositorios en %s", self.repos_path)

        return repositorios

    def run_gitleaks(self, repo_path: str) -> str:
        repo_name = Path(repo_path).name
        LOGGER.info("Ejecutando Gitleaks en el repositorio: %s", repo_name)
        repo_path = self.project_root / repo_path

        if not repo_path.exists():
            LOGGER.error("El repositorio %s no existe.", repo_path)
            return ""

        try:
            resultado = subprocess.run(
                ["gitleaks", "detect", "-s",
                    str(repo_path), "-f", "json", "-r", f"{self.results_path}/{repo_name}_gitleaks.json"],
                capture_output=True,
                text=True,
                check=False
            )
            LOGGER.info("Gitleaks completado para %s", repo_name)
            return resultado.stdout
        except Exception as e:
            LOGGER.error("Error al ejecutar Gitleaks en %s: %s", repo_path, e)
            return ""

    def run(self):
        repositorios = self.discover_repositorioes()
        resultados = {}

        for repo in repositorios:
            LOGGER.info("Analizando el repositorio: %s", repo)
            resultado = self.run_gitleaks(repo)
