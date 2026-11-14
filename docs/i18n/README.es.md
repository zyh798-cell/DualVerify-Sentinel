<div align="center">

<img src="../../assets/logo.svg" alt="DualVerify-Sentinel logo — deep navy shield with dual verification check, cyan orbit nodes and the DVS wordmark" width="110">

# DUALVERIFY-SENTINEL

### ENGINEERED FOR TRUST.
### BUILT FOR CONTROL.

**Un motor de validación de seguridad basado en autorización explícita, ejecución determinista y evidencia verificable.**

Ejecución determinista. Límites de autorización explícitos. Evidencia de seguridad auditable.

`zyh798-cell` / `DualVerify-Sentinel` · MIT

<img src="../../assets/banner.svg" alt="DualVerify-Sentinel banner — shield mark, project name, one-line description and authorized-testing-only notice" width="720">

[![Star on GitHub](https://img.shields.io/badge/Star_on-GitHub-181717?style=for-the-badge&logo=github)](https://github.com/zyh798-cell/DualVerify-Sentinel)
[![Star](https://img.shields.io/badge/Star-grey?style=for-the-badge&logo=github)](https://github.com/zyh798-cell/DualVerify-Sentinel)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-085041)](#sec-7)
[![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-0C447C)](#sec-3)
[![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-BA7517)](#sec-5)
[![Status](https://img.shields.io/badge/Status-Gen--1-0C447C)](#sec-8)

[English](../../README.md) · [中文](README.zh-CN.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · **Español** · [Français](README.fr.md)

[Descripción general](#sec-1) · [Capacidades](#sec-2) · [Inicio rápido](#sec-4) · [Seguridad](#sec-5) · [Pruebas de plataforma](#sec-7) · [Contribuir](#sec-9) · [Security](../../SECURITY.md)

> ⭐ **Si este proyecto te resulta útil, dale una estrella. Las pruebas de la comunidad y las contribuciones son bienvenidas.**

> ⚠️ **SOLO PARA PRUEBAS DE SEGURIDAD AUTORIZADAS**

</div>

---

<a id="sec-1"></a>
## 1. ¿Qué es DualVerify-Sentinel?

DualVerify-Sentinel (DVS) es un **motor de validación de seguridad basado en
políticas**: cada paso de ejecución se comprueba contra un alcance de
autorización legible por máquina, se registra en un diario de evidencias
resistente a manipulaciones y aplica **cierre ante fallos (fail-closed)** — si
falta, está corrupto o ha caducado la autorización, se produce un rechazo, nunca
una comprobación omitida.

Es una capa base de ingeniería de seguridad: una puerta de autorización más un
motor de ejecución determinista. La planificación de Gen-1 es una **plantilla
estática basada en reglas**, no un planificador basado en modelos ni adaptativo.

**Lo que DVS no es hoy**: una plataforma de agentes de propósito general, un
runtime de agentes LLM, un sistema de decisión autónoma basado en modelos ni un
sandbox a nivel de sistema operativo. Son direcciones a largo plazo, no
capacidades actuales.

<a id="sec-2"></a>
## 2. Lo que hace hoy

Cada capacidad se aplica mediante rutas de código explícitas, no por juicio de un modelo.

| Capacidad | Qué está implementado |
|---|---|
| **Autorización explícita** | JSON de alcance validado en un **subproceso aislado**; hash del alcance, modo, objetivo y ventana se vuelven a verificar de forma independiente en tiempo de ejecución. Alcance ausente, corrupto o caducado → RECHAZO. No existe ruta de evasión. |
| **Ejecución basada en políticas** | Cinco modos con techos de riesgo crecientes: `passive` (R0), `safe_scan` (R1), `vuln_validation` (R2), `attack_simulation` (R3), `high_risk` (R4). Reglas de decisión explícitas detienen el bucle ante rechazo, aborto o fallo; los objetivos nunca se amplían. |
| **Controles con conciencia de riesgo** | Máquina de estados TaskGraph con límites estrictos (máx. 32 nodos, profundidad de derivación 2, 8 derivaciones), derivaciones dinámicas condicionadas al estado COMPLETED del padre y una cadena de 12 comprobaciones por paso. Sin técnicas destructivas, sin persistencia, sin construcción de payloads, sin exfiltración de datos hallados. |
| **Integración de herramientas de seguridad** | Adaptadores principales `nuclei` y `bandit`; adaptadores opcionales `gitleaks` y `semgrep` en `vuln_hunter/adapters_ext/` (solo archivos de reglas locales, sin descarga de reglas por red). Toda salida se normaliza mediante el Finding Schema unificado (`findings.py`). Si falta un binario se omite limpiamente con un informe previo. |
| **Evidencia de auditoría verificable** | Cadena de hash SHA-256 de solo adición (`seq` / `prev` / `h`) con detección de manipulación y reordenación. Un fallo de auditoría termina con código 3 en lugar de presentar un resultado no certificado como normal. |
| **Informes honestos y estructurados** | Los hallazgos se registran tal cual; la salida no verificada nunca se etiqueta como vulnerabilidad confirmada; cada informe enumera las limitaciones conocidas; no se afirma corrección de detección ni exactitud. |

> Los adaptadores están **implementados como código**. Su presencia no es prueba
> de una ejecución verificada con la herramienta real; la verificación
> end-to-end con herramientas reales no se ha completado (véase la sección 8).

<a id="sec-3"></a>
## 3. Requisitos

| Requisito | Detalle |
|---|---|
| Python | >= 3.10 (verificado en 3.13.14) |
| Dependencias | **Solo biblioteca estándar** — sin dependencias de terceros en ejecución |
| SO | Windows **verificado**; Linux / macOS **aún no verificados** — véase la sección 7 |
| Herramientas externas opcionales | `nuclei`, `bandit`, `gitleaks`, `semgrep` — se omiten limpiamente si no están |

<a id="sec-4"></a>
## 4. Instalación e inicio rápido

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows (PowerShell): .venv\Scripts\Activate.ps1
# Windows (CMD):        .venv\Scripts\activate.bat
# Linux/macOS:          source .venv/bin/activate

pip install .
```

`pip install -e .` también está disponible para desarrollo.

**Paso 1 — valida siempre primero el archivo de alcance:**

```bash
dvs gate-check scripts/example-scope.json
# 0 = válido · 1 = rechazado · 2 = error de uso
```

**Paso 2 — ejecuta una validación:**

```bash
dvs run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# o: python -m vuln_hunter run --scope ... --mode ... --target ...
```

Modos (techo de riesgo creciente): `passive` → `safe_scan` →
`vuln_validation` → `attack_simulation` → `high_risk` (R0–R4). `nuclei` solo se
invoca a partir de R2.

Códigos de salida: `0` todos los pasos COMPLETED · `1` finalizó con fallos/rechazos ·
`2` rechazo de puerta/política (nada ejecutado) · `3` **fallo de auditoría** (el
diario no se puede escribir o verificar, por lo que los resultados no se certifican).

`scripts/example-scope.json` es un ejemplo ficticio, **no una autorización real**.

<a id="sec-5"></a>
## 5. Autorización y seguridad

> ⚠️ **Usa DVS solo contra sistemas que poseas u operes, objetivos de laboratorio
> locales, o hosts para los que tengas autorización escrita y explícita del propietario.**

Las configuraciones no autorizadas, fuera de alcance, con ventana caducada o
corruptas se rechazan. No existe una ruta de código que omita la autorización.

- Las entradas se comparan por **igualdad de nombre de host ya parseado**; una
  entrada sin puerto coincide con cualquier puerto de ese host. **No se admiten
  rangos CIDR** — usa entradas `host` u `host:port`.
- La ventana de autorización se vuelve a comprobar **en cada paso de ejecución**;
  si caduca durante la ejecución se abortan los pasos restantes.
- El contenido del alcance queda ligado por hash a cada ticket de ejecución;
  modificar el alcance invalida los tickets pendientes.
- Los pasos con alcance de sistema de archivos omiten únicamente la comprobación
  de alcance de red; las demás comprobaciones de política siguen aplicándose.

Guarda los registros de autorización reales fuera de este repositorio. El alcance
de ejemplo incluido es ficticio.

**El endurecimiento de API no es un sandbox a nivel de SO.** El dataclass
congelado de `RunTicket` y su registro privado son endurecimiento a nivel de
Python; código hostil en el mismo proceso podría eludirlos. Un aislamiento fuerte
requiere medidas a nivel de proceso, aún no implementadas. La CLI es el único
punto de entrada soportado.

<a id="sec-6"></a>
## 6. Evidencias e informes honestos

El diario de auditoría es de solo adición y está encadenado por hash; manipular o
reordenar entradas se detecta, y un fallo de auditoría se expone explícitamente
en lugar de ocultarse. Los informes distinguen resultados completos, parciales e
incompletos; los resultados incompletos cierran ante fallos y no aportan hallazgos.

Dos límites conviene declararlos claramente: la salida de las herramientas se
registra tal cual y una salida no verificada nunca se promueve a vulnerabilidad
confirmada; y el truncamiento de la cola del diario solo puede detectarse si se
ha guardado externamente un ancla de cabecera.

<a id="sec-7"></a>
## 7. Compatibilidad de plataformas y pruebas de la comunidad

**Las pruebas de la comunidad son bienvenidas. Ayúdanos a ampliar la compatibilidad de plataformas.**

DVS es actualmente **Windows-first**. En Windows, la ruta de timeout realiza una
limpieza registrada del árbol de procesos (`taskkill /T /F` se ejecuta antes de
terminar el proceso raíz, con cada resultado registrado); el comportamiento se
ejercitó en un ensayo controlado pero no garantiza de forma absoluta la ausencia
de residuos. En plataformas no Windows se omite la terminación del árbol y solo
se termina el proceso raíz. El fallback de ruta de `nuclei` además asume una
distribución local concreta.

Linux y macOS **no se han verificado** y CI aún no los cubre. Si ejecutas DVS en
otra plataforma, comparte en un issue qué funciona y qué no — el comportamiento
de adaptadores, la limpieza de procesos y el empaquetado son especialmente útiles.
No incluyas datos de objetivos reales, credenciales ni salidas de escaneos no autorizados.

<a id="sec-8"></a>
## 8. Estado del proyecto y dirección

| | |
|---|---|
| **Entregado (Gen-1)** | Puerta de autorización, motor de políticas (R0–R4), TaskGraph, diario de auditoría, informes estructurados, Finding Schema unificado y rutas de código de los adaptadores `nuclei` / `bandit` / `gitleaks` / `semgrep`. |
| **En construcción / verificación** | Verificación end-to-end con herramientas reales, verificación y CI para plataformas no Windows, y verificación de empaquetado de esta versión exacta. Las suites de pruebas están en `tests/` — ejecútalas y confía en su salida real; este repositorio no afirma de antemano que «todo esté en verde». |
| **Dirección a largo plazo** | Planificación basada en modelos, aislamiento más fuerte a nivel de proceso y mayor cobertura de plataformas. Son solo direcciones y **no están implementadas** en Gen-1. |

La capa de planificación actual es una plantilla estática determinista. La
presencia de código de adaptador no prueba una ejecución verificada de la
herramienta, y el endurecimiento de API no es un sandbox a nivel de SO. El
empaquetado debe juzgarse construyendo esta versión; artefactos de compilación
antiguos no son evidencia para la versión actual. Es una base de ingeniería, no un
producto de evaluación listo para producción.

<a id="sec-9"></a>
## 9. Contribuir y participar

Una estrella ayuda a que otras personas encuentren el proyecto. Probar DVS en tus
propios objetivos de laboratorio, contar lo que observas y abrir un pull request
son igualmente bienvenidos. Consulta [CONTRIBUTING.md](../../CONTRIBUTING.md) para
la guía completa.

Formas de ayudar:

- **Adaptación de plataformas y pruebas de compatibilidad** — comportamiento en
  Linux/macOS, limpieza del árbol de procesos, empaquetado.
- **Integración de proveedores / adaptadores de herramientas de seguridad** —
  nuevas integraciones que respeten la puerta de autorización y el diseño fail-closed.
- **Casos de prueba y bases de regresión** — comprobaciones repetibles que produzcan evidencias.
- **Documentación y traducciones** — los seis idiomas del README, ejemplos y claridad.
- **Corrección de errores y calidad de código** — cambios pequeños y enfocados con evidencia ejecutable.
- **Investigación en seguridad** — sigue [SECURITY.md](../../SECURITY.md); nunca abras un issue público para una vulnerabilidad no divulgada.
- **Experiencia de uso e ideas de funcionalidades** — abre antes un issue para acordar el alcance.

Usa **Issues** para errores, resultados de plataforma y propuestas; usa **Pull
Requests** para cambios de código y documentación. No adjuntes datos de objetivos
reales, credenciales, registros de autorización privados ni salidas de escaneos
no autorizados a ningún issue o PR.

<a id="sec-10"></a>
## 10. Licencia y enlaces

- **Licencia**: MIT — véase [LICENSE](../../LICENSE).
- **Política de seguridad**: [SECURITY.md](../../SECURITY.md).
- **Guía de contribución**: [CONTRIBUTING.md](../../CONTRIBUTING.md).
- **Issues y PR**: [abrir un issue](https://github.com/zyh798-cell/DualVerify-Sentinel/issues) · [abrir un PR](https://github.com/zyh798-cell/DualVerify-Sentinel/pulls).
- **Traducciones**: 中文 · 日本語 · 한국어 · Español · Français (véase el selector de idioma arriba).

---

<div align="center"><sub>DualVerify-Sentinel · Engineered for Trust. Built for Control. · MIT © 2026 zyh798-cell</sub></div>
