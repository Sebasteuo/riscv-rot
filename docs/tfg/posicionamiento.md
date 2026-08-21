# Posicionamiento frente al estado del arte

**Etapa 1, punto 2** · TFG CE-5600 · Sebastián Alba Vives
22 de agosto de 2026

---

## 1. Cómo está organizado

Mi trabajo cruza dos linajes que hasta ahora corrieron separados: las raíces
de confianza en RISC-V y la clasificación de comportamiento con contadores de
hardware. Me posiciono contra los dos por separado y después contra los pocos
trabajos que los cruzan.

---

## 2. Linaje A: raíces de confianza en RISC-V

| Trabajo | Venue | Qué hace | En qué difiere de lo mío |
|---|---|---|---|
| Sanctum | USENIX Sec 2016 | Security monitor en M-mode con extensiones mínimas de hardware | Fija el patrón que heredo. Necesita extensiones de hardware propias |
| Keystone | EuroSys 2020 | TEE con solo PMP y M-mode, enclaves dinámicos | La referencia obligada. Necesita sistema operativo debajo y apunta a enclaves multiusuario |
| OpenTitan | Documentación oficial | RoT de silicio, cadena ROM → ROM_EXT → BL0 con firma | El modelo de despliegue real para mi OE1. Es un chip completo, cerrado, no replicable |
| fTPM | USENIX Sec 2016 | TPM 2.0 completo en firmware sobre TrustZone | Precedente de TPM en firmware. Requiere TrustZone y sistema operativo |
| fTPM en RISC-V | DATE 2021 | TPM de firmware para RISC-V | **Es una propuesta de diseño, no implementación.** Depende de OP-TEE y sistema operativo enriquecido. Los autores declaran el port de OP-TEE como trabajo futuro |
| LIRA-V | IEEE SPW 2021 | Attestation remota en RISC-V restringido, ROM y PMP como ancla | Lo más cercano a mi escenario. Es attestation estática de desafío y respuesta, no de runtime |
| Secure boot ligero | ISQED 2019 | Cadena de arranque firmada en SoC RISC-V, ECDSA y SHA-3 | **Confirma que la firma asimétrica es el enfoque correcto.** Lo resuelven con un bloque de hardware dedicado; lo mío es software puro en M-mode |

**Dónde me paro.** El nicho es un Root of Trust bare-metal, abierto y
reproducible: sin sistema operativo debajo como Keystone, y sin silicio
cerrado como OpenTitan. El trabajo de DATE 2021 es el que apunta al mismo
lugar, pero es un diseño que depende de OP-TEE. Mi plataforma corre sin
sistema operativo y sin biblioteca estándar de C.

---

## 3. Linaje B: contadores de hardware y clasificación

| Trabajo | Venue | Qué hace | En qué difiere de lo mío |
|---|---|---|---|
| Demme y coautores | ISCA 2013 | Funda el campo. Series de contadores más clasificadores detectan malware | x86 y ARM con sistema operativo completo. Supervisado. Detección de malware, no attestation |
| Tang y coautores | RAID 2014 | Detección no supervisada de una sola clase, modela solo lo benigno | **El más cercano en método.** Sus features arquitecturales coinciden casi una a una con las mías. x86 con sistema operativo |
| NumChecker | DAC 2013 | Cuenta eventos entre puntos de control del flujo privilegiado | Emparejamiento de perfiles, sin aprendizaje. Kernel de Linux |
| ConFirm | ICCAD 2015 | Detecta modificaciones de firmware embebido con contadores | **Valida mi decisión arquitectónica:** el detector vive en el bootloader. Pero compara contra firmas guardadas, sin aprendizaje, e instrumenta el firmware vigilado |
| Zhou y coautores | AsiaCCS 2018 | Resultado negativo: en Linux multiproceso los contadores no separan benigno de malicioso | Su argumento de causalidad es función de la entropía de la carga. Un firmware fijo y determinista está en el extremo opuesto |
| Das y coautores | IEEE S&P 2019 | Sistematiza las fallas de usar contadores en seguridad | **La cita defensiva obligatoria.** Dos de sus cuatro problemas no aplican en bare-metal y los otros dos los acoté experimentalmente |
| Basu y coautores | IEEE TIFS 2020 | Marco analítico de robustez de la detección | Mi contrapeso a las dos críticas anteriores. Su garantía asume que el atacante desconoce qué contadores se observan |

**Dónde me paro.** Todo este linaje corre sobre sistemas con sistema
operativo y con el clasificador fuera del dispositivo o en el procesador
mismo, nunca dentro de una raíz de confianza.

---

## 4. Los trabajos que cruzan los dos linajes

Son cuatro, y son los que definen mi novedad.

| Trabajo | Plataforma | Dónde vive el clasificador | Qué evidencia usa |
|---|---|---|---|
| **CHARM** · ACM TECS 2023 | ARM Cortex-M33 | En el verificador | Contadores, para tolerar interrupciones de la attestation por hash |
| **LightFAt** · IEEE HOST 2024 | x86-64 con CentOS | En el verificador | IPC y accesos a caché L1, microarquitecturales |
| **LightFAt+** · ACM TCPS 2026 | x86-64 y ARM Cortex-A78 | En el verificador | Igual, extendido a ARM |
| **HPCCFA** · arXiv 2026, sin arbitrar | RISC-V, enclave Keystone | Genera trazas, no clasifica | Instrucciones, branches y cargas retiradas |
| **Este trabajo** | **RISC-V bare-metal, M-mode con PMP** | **Dentro del Root of Trust** | **Eventos arquitecturales sintetizados** |

### Detalle de cada uno

**CHARM** es el antecedente más cercano en objetivo. Usa contadores del lado
del dispositivo y aprendizaje del lado del verificador. Pero su meta es hacer
viable una attestation por hash que se pueda interrumpir, no clasificar
estado de integridad. Corre sobre Cortex-M33, no RISC-V, y no está planteado
como servicio de Root of Trust.

**LightFAt y LightFAt+** son el puente más directo publicado entre
contadores, aprendizaje y attestation. El primer autor tiene afiliación con
el TEC y es la contraparte de este proyecto. Usan solo dos features, ambas
microarquitecturales, y el clasificador corre en el verificador. La versión
de revista extiende la evaluación a ARM Cortex-A78, que sigue siendo un
núcleo de aplicación con sistema operativo.

**HPCCFA** es el más cercano en plataforma y apareció en marzo de 2026. Usa
contadores para attestation de flujo de control **sobre RISC-V**, lo que hasta
ahora nadie había hecho. Tres diferencias: corre dentro de un enclave
Keystone, o sea con security monitor y sistema operativo; genera trazas de
flujo de control en vez de clasificar con un modelo; y no está arbitrado.
Conviene reconocer algo en lo que me superan: evalúan sobre silicio real,
mientras que este trabajo evalúa sobre emulación instrumentada.

---

## 5. Los tres ejes que me distinguen

Después de este recorrido, la novedad se sostiene en tres ejes y conviene
enunciarlos así de acotados.

**Eje 1 · Plataforma.** RISC-V bare-metal en M-mode con PMP, sin sistema
operativo ni security monitor debajo. CHARM está en Cortex-M, LightFAt en
x86 y ARM con sistema operativo, HPCCFA dentro de un enclave Keystone.

**Eje 2 · Dónde decide.** El clasificador corre **dentro del Root of Trust**,
en el dispositivo. Los tres trabajos anteriores lo ponen en el verificador o
no clasifican. Esto es una afirmación más fuerte que la de CHARM y obliga a
justificar el presupuesto de memoria y ciclos.

**Eje 3 · Qué se observa.** Eventos arquitecturales, no microarquitecturales.
No es preferencia estética: en emulación funcional lo microarquitectural no
existe de forma significativa. La elección está forzada por la plataforma y
hay que argumentarla así.

---

## 6. Lo que no puedo reclamar

Por honestidad, y porque un lector informado lo va a verificar.

- **No soy el primero en usar contadores como evidencia de attestation.**
  LightFAt reclama eso explícitamente.
- **No soy el primero en usar contadores sobre RISC-V para attestation.**
  HPCCFA llegó antes, aunque sin arbitraje.
- **No evalúo sobre silicio real.** HPCCFA sí. Esa es una limitación declarada
  desde el anteproyecto y queda como trabajo futuro.
