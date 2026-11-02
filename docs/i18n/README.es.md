<div align="center">

# DualVerify-Sentinel

**Motor de validación de seguridad determinista con control de autorización.**

`zyh798-cell` / `DualVerify-Sentinel` · Gen-1 Estable · MIT

<img src="../../assets/banner.gif" alt="DualVerify-Sentinel — banner animado estilo píxel donde el título aparece letra a letra con una línea de barrido y flujos de datos" width="720">

**DualVerify-Sentinel — Deterministic Security Validation Engine**
⚠️ **SOLO PRUEBAS DE SEGURIDAD AUTORIZADAS**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-0078D6?logo=windows&logoColor=white)](#4-requisitos)
[![Platform](https://img.shields.io/badge/Platform-Linux%2FmacOS%20Unverified-6b7280)](#10-limitaciones-conocidas)
[![Checks](https://img.shields.io/badge/Offline%20Checks-427%2B%20Passing-2EA043)](#11-estado-del-proyecto)
[![Status](https://img.shields.io/badge/Status-Gen--1%20Stable-8250DF)](#11-estado-del-proyecto)

[English](../../README.md) · [中文](README.zh-CN.md) · [日本語](README.ja.md) · **Español** · [Français](README.fr.md)

</div>

---

## 1. Qué es esto

DualVerify-Sentinel es un **motor de validación de seguridad basado en reglas**
(explícitamente **NO dirigido por modelos**): cada paso de ejecución se valida
contra un alcance de autorización legible por máquina, se registra en un diario de
auditoría con cadena de hash a prueba de manipulaciones, y funciona con
**fail-closed** — la autorización ausente, corrupta o expirada significa
*rechazo*, nunca una comprobación omitida.

Es la capa de ingeniería de seguridad (puerta de autorización + motor de
ejecución fiable) de una arquitectura de verificación de nueva generación
planificada. La capa de planificación/decisión de Gen-1 es deliberadamente
determinista.

## 2. Qué puede hacer

| Capacidad | Cómo funciona |
|---|---|
| Puerta de autorización | El JSON de alcance legible por máquina se valida en un **subproceso aislado**; ausente/corrupto/expirado → REFUSED (código de salida 2). No existe ruta de omisión. |
| Tickets de ejecución | Los adaptadores solo aceptan tickets emitidos por el motor de políticas; hash de alcance, modo, objetivo y ventana se **reverifican de forma independiente en tiempo de ejecución**. |
| Ejecución segura | Cadena de 12 comprobaciones por paso; sin técnicas destructivas, sin persistencia, sin construcción de payloads, sin exfiltración de datos descubiertos. |
| Diario de auditoría | Cadena de hash de solo adición (`seq`/`prev`/`h`, SHA-256); detección de manipulación/reordenación; un fallo de auditoría termina con el código 3 en lugar de disfrazarse como resultado normal. |
| Bucle de decisión determinista | Reglas explícitas P0–P8: cualquier rechazo/aborto/fallo detiene el bucle; los objetivos **nunca** se amplían. |
| Grafo de tareas | Máquina de estados con presupuestos estrictos (máx. 32 nodos, profundidad de spawn 2, 8 spawns); los spawns dinámicos requieren un padre COMPLETED. |
| Adaptadores de herramientas opcionales | `nuclei` (escaneo de plantillas) y `bandit` (análisis estático) — se omiten (SKIPPED) elegantemente con informe de preflight si no están instalados. |
| Informes honestos | Los hallazgos se registran tal cual; la salida no verificada nunca se etiqueta como vulnerabilidad confirmada; las limitaciones conocidas se listan en cada informe. |

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
| Herramientas externas (opcional) | `nuclei`, `bandit` — se omiten si no están presentes |

## 5. Instalación

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows:
.venv\Scripts\activate
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
2. **Windows primero** — la eliminación por tiempo de espera no rastrea procesos
   nietos en Windows; la ruta de reserva de nuclei asume un diseño local
   `~/Tools/nuclei/`.
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

- **Gen-1 es estable**: 18 suites de pruebas fuera de línea, 427+ comprobaciones
  aprobadas localmente (Windows, Python 3.13.14). Empaquetado probado mediante
  compilaciones wheel/sdist.
- Se planifica una **arquitectura Gen-2** (un repositorio futuro e independiente)
  con separación de propuesta/adjudicación. El trabajo de Gen-2 no ocurrirá en
  este repositorio.
- Los comandos de prueba completos están en las suites bajo `tests/` — ejecútelos
  y confíe en los resultados reales; este repositorio no hace afirmaciones
  preventivas de "todo en verde".

## 12. Licencia y comentarios

- **Licencia**: MIT — ver [LICENSE](../../LICENSE).
- **Política de seguridad**: ver [SECURITY.md](../../SECURITY.md).
- Issues y pull requests son bienvenidos. Para reportes relacionados con
  seguridad, siga la guía de SECURITY.md en lugar de abrir un issue público.

---

<div align="center">
<sub>DualVerify-Sentinel · Deterministic Security Validation Engine · MIT © 2026 zyh798-cell</sub>
</div>
