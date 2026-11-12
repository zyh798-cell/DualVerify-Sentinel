<div align="center">

<img src="../../assets/logo.svg" alt="Logotipo de DualVerify-Sentinel — hexágono de verificación con doble marca de verificación, nodos de red y banda de escaneo" width="110">

# DUALVERIFY-SENTINEL

### ENGINEERED FOR TRUST.
### BUILT FOR CONTROL.

**Motor de validación de seguridad dirigido por políticas**

Ejecución determinista. Límites de autorización explícitos. Evidencia de seguridad auditable.

`zyh798-cell` / `DualVerify-Sentinel` · MIT

<img src="../../assets/banner.gif" alt="DualVerify-Sentinel — banner animado: revelación del título en píxeles, línea de barrido y flujos de datos" width="720">

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-085041)](#4-requisitos)
[![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-0C447C)](#4-requisitos)
[![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-BA7517)](#8-autorización-y-seguridad)
[![Status](https://img.shields.io/badge/Status-Gen--1-0C447C)](#11-estado-del-proyecto)

[English](../../README.md) · [中文](README.zh-CN.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · **Español** · [Français](README.fr.md)

[Autorización](#puerta-de-autorización) · [Motor de políticas](#motor-de-políticas-y-escala-de-riesgo) · [TaskGraph](#orquestación-taskgraph) · [Adaptadores](#adaptadores-de-herramientas-nuclei--bandit) · [Auditoría](#diario-de-auditoría) · [Informes](#informes-estructurados) · [Instalación](#5-instalación) · [Seguridad](../../SECURITY.md)

> ⚠️ **SOLO PRUEBAS DE SEGURIDAD AUTORIZADAS**

</div>

---

## 1. Qué es esto

DualVerify-Sentinel es un **motor de validación de seguridad basado en reglas**
(explícitamente **NO dirigido por modelos**): cada paso de ejecución se valida
contra un alcance de autorización legible por máquina, se registra en un diario de
auditoría con cadena de hash a prueba de manipulaciones, y funciona con
**fail-closed** — la autorización ausente, corrupta o expirada significa
*rechazo*, nunca una comprobación omitida.

Es una capa de ingeniería de seguridad: una puerta de autorización más un motor
de ejecución determinista. La capa de planificación/decisión de Gen-1 es
deliberadamente determinista, no dirigida por modelos.

## 2. Qué puede hacer

Gen-1 se ejecuta como un único flujo determinista — cada capacidad siguiente se aplica mediante rutas de código explícitas, no por juicio de un modelo.

### Puerta de autorización

El JSON de alcance legible por máquina se valida en un **subproceso aislado**; ausente/corrupto/expirado → REFUSED (código de salida 2). No existe ruta de omisión. Los adaptadores solo aceptan tickets emitidos por el motor de políticas; el hash de alcance, el modo, el objetivo y la ventana se **reverifican de forma independiente en tiempo de ejecución**.

### Motor de políticas y escala de riesgo

Cinco modos con techo de riesgo creciente (R0–R4, véase [Uso básico](#6-uso-básico)). Reglas explícitas P0–P8: cualquier rechazo/aborto/fallo detiene el bucle; los objetivos **nunca** se amplían.

### Orquestación TaskGraph

Máquina de estados con presupuestos estrictos (máx. 32 nodos, profundidad de spawn 2, 8 spawns); los spawns dinámicos requieren un padre COMPLETED.

### Adaptadores de herramientas (nuclei / bandit)

`nuclei` (escaneo de plantillas) y `bandit` (análisis estático) — se omiten (SKIPPED) elegantemente con informe de preflight si no están instalados. Ejecución segura: cadena de 12 comprobaciones por paso; sin técnicas destructivas, sin persistencia, sin construcción de payloads, sin exfiltración de datos descubiertos.

### Diario de auditoría

Cadena de hash de solo adición (`seq`/`prev`/`h`, SHA-256); detección de manipulación/reordenación; un fallo de auditoría termina con el código 3 en lugar de disfrazarse como resultado normal.

### Informes estructurados

Los hallazgos se registran tal cual; la salida no verificada nunca se etiqueta como vulnerabilidad confirmada; las limitaciones conocidas se listan en cada informe.

### Adaptadores adicionales y esquema unificado de hallazgos

En `vuln_hunter/adapters_ext/` se implementan otros dos adaptadores opcionales:
`gitleaks` (detección de secretos, paso `s4-gitleaks`) y `semgrep` (análisis
estático, **solo con archivos de reglas locales**, paso `s5-semgrep`). Ambos se
planifican de forma condicional para árboles de código fuente con alcance de
sistema de archivos, requieren sus propios binarios y nunca obtienen reglas por
red. Toda salida de adaptador se normaliza mediante el esquema unificado de
hallazgos (`findings.py`), que valida la severidad y la forma del registro antes
de que un hallazgo llegue a un informe.

> Estos adaptadores están **implementados como código**; la verificación de
> extremo a extremo con herramientas reales **no se ha completado**. La presencia
> de un adaptador no es prueba de una ejecución verificada — véase la sección 11.

## 3. Casos de uso

- Validar sus propios objetivos de laboratorio y hosts explícitamente autorizados.
- Ejecutar comprobaciones de seguridad repetibles, con evidencia y rastro de
  auditoría completo.
- Como capa base para construir canalizaciones de verificación de nivel superior.

## 4. Requisitos

| Requisito | Detalle |
|---|---|
| Python | >= 3.10 (probado solo en 3.13.14) |
| Dependencias de terceros | **Ninguna** — solo biblioteca estándar |
| Sistema operativo | Windows **Verificado**; Linux/macOS **Aún no verificado** |
| Herramientas externas (opcional) | `nuclei`, `bandit`, `gitleaks`, `semgrep` — adaptadores implementados; se omiten si no están presentes; ejecuciones con herramientas reales aún no verificadas |

## 5. Instalación

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (CMD):
.venv\Scripts\activate.bat
# Linux/macOS:
source .venv/bin/activate

pip install .
```

Para desarrollo también está disponible la instalación editable `pip install -e .`.

## 6. Uso básico

**Paso 1 — validar el archivo de alcance (hágalo siempre primero):**

```bash
dvs gate-check scripts/example-scope.json
# código de salida 0 = alcance válido · 1 = rechazado
```

**Paso 2 — ejecutar una validación:**

```bash
dvs run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# o: python -m vuln_hunter run --scope ... --mode ... --target ...
```

Modos (techo de riesgo creciente): `passive` → `safe_scan` → `vuln_validation` →
`attack_simulation` → `high_risk` (R0–R4). `nuclei` solo se invoca en R2 o superior.

Códigos de salida: `0` todos los pasos COMPLETED · `1` terminado con
fallos/rechazos · `2` rechazo a nivel de puerta/política (no se ejecutó nada) ·
`3` **fallo de auditoría** (diario no escribible/no verificable — los resultados
no se certifican).

`scripts/example-scope.json` es un ejemplo ficticio — **no es una autorización
real**.

## 7. Semántica del alcance

- Las entradas se comparan por **igualdad de nombre de host analizado** (una
  entrada sin puerto coincide con cualquier puerto de ese host). **NO se admiten
  rangos CIDR** — use entradas `host` o `host:puerto`.
- La ventana de autorización se **revisa en cada paso de ejecución**; la
  expiración a mitad de ejecución aborta los pasos siguientes.
- El hash del contenido del alcance se vincula a cada ticket; cambiar el alcance
  invalida los tickets pendientes.
- Los pasos con alcance de sistema de archivos omiten solo la comprobación de
  alcance de red; todas las demás comprobaciones de política siguen aplicándose.

## 8. Autorización y seguridad

> ⚠️ **Use esta herramienta SOLO contra sistemas que posea u opere, objetivos de
> laboratorio locales, o hosts para los que tenga autorización expresa por
> escrito del propietario.** Las configuraciones no autorizadas, fuera de
> alcance, con ventana expirada o corruptas se rechazan (fail-closed). No existe
> ninguna ruta de código que omita la autorización.

El alcance de ejemplo incluido es ficticio. Los encargos reales requieren un
registro de autorización real y legible por máquina — manténgalo fuera de este
repositorio.

## 9. El endurecimiento de API NO es una sandbox

El frozen dataclass de RunTicket y su registro privado son **refuerzo de API**,
no una sandbox — el código hostil en el mismo proceso puede eludir cualquier
comprobación a nivel de Python. Un aislamiento fuerte requiere medidas a nivel de
proceso (no implementadas). La CLI es el único punto de entrada soportado.

## 10. Limitaciones conocidas

1. **Sin sandbox en el proceso** — ver sección 9.
2. **Windows primero** — la ruta de tiempo de espera en Windows realiza una
   limpieza de árbol de procesos equipada sobre el terreno (`taskkill /T /F` se
   ejecuta antes de matar la raíz, con todos los resultados registrados); está
   verificada en un simulacro controlado de árbol de tres niveles, pero **no es
   una garantía absoluta** — sin comprobación de residuos en tiempo de
   ejecución, `rc=0` no prueba que todo el árbol quedara limpio, y las formas
   reales de los descendientes de Nuclei no están verificadas. En plataformas
   que no son Windows se omite el kill de árbol (solo raíz). La ruta de reserva
   de nuclei asume un diseño local `~/Tools/nuclei/`.
3. **Sin promesa de corrección de detección** — la salida de herramientas se
   registra textualmente; los resultados no verificados nunca se marcan como
   vulnerabilidades confirmadas.
4. **Linux/macOS sin verificar** — la CI no cubre plataformas que no sean Windows.
5. **Truncamiento de la cola del diario** — detectable solo si se guardó un ancla
   head externa; las anclas del informe son solo para comprobaciones de
   consistencia.
6. **El planificador de Gen-1 es una plantilla estática** — la planificación es
   determinista, no dirigida por modelos ni adaptativa.

## 11. Estado del proyecto

- **Gen-1 está implementado**: la puerta de autorización, el motor de políticas
  (R0–R4), TaskGraph, el diario de auditoría, los informes estructurados, el
  esquema unificado de hallazgos y los adaptadores `nuclei` / `bandit` /
  `gitleaks` / `semgrep` existen como rutas de código. Las suites de pruebas están
  en `tests/` — ejecútelas y confíe en la salida real; este repositorio no hace
  afirmaciones preventivas de «todo en verde» ni de recuentos de comprobaciones.
- **No verificado / no implementado**: la verificación de extremo a extremo con
  herramientas reales no se ha completado; la Fase B no se ha ejecutado; los
  elementos W1-03, W1-04, W1-06 y CR-06 y la línea base real de Semgrep siguen
  abiertos; la verificación en Linux/macOS y el CI no están implantados; Gen-2 no
  está implementado en este repositorio. La presencia de código de adaptador no es
  prueba de una ejecución verificada, y el endurecimiento de API no es una sandbox
  a nivel de sistema operativo (véase la sección 9).
- El empaquetado debe juzgarse mediante una compilación de esta versión; los
  artefactos de compilación antiguos no son prueba para la versión actual.

## 12. Licencia y comentarios

- **Licencia**: MIT — ver [LICENSE](../../LICENSE).
- **Política de seguridad**: ver [SECURITY.md](../../SECURITY.md).
- **Contribuir**: ver [CONTRIBUTING.md](../../CONTRIBUTING.md).
- Issues y pull requests son bienvenidos. Para reportes relacionados con
  seguridad, siga la guía de SECURITY.md en lugar de abrir un issue público.

---

<div align="center">
<sub>DualVerify-Sentinel · Deterministic Security Validation Engine · MIT © 2026 zyh798-cell</sub>
</div>
