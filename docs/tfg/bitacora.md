# Bitácora TFG - CE-5600 - II Semestre 2026

Acá voy anotando lo que hago cada día. Esto es lo que después uso para
armar los informes de avance.

---

## Semana 1 (3 al 9 de agosto)

Arrancó el semestre de TFG. Esta semana fue puro papeleo: leí los
lineamientos completos, armé un calendario con todas las fechas de entrega
y me puse a ver cómo iba a organizar el semestre. Todavía no toqué código.

## Semana 2 (10 al 16 de agosto)

Le mandé al profe Solano la lista de profesores que no quiero que me
asignen como asesor. Me confirmó q le llegó.

El resto de la semana lo dediqué a preparar el video del anteproyecto. Armé
una presentación y el guion, tratando de q entraran los 5 puntos que piden
en 2 minutos y medio, q es poquísimo tiempo.

## Semana 3 (17 al 23 de agosto)

### Lunes 17

Subí el video del anteproyecto. Entregado a tiempo.

### Martes 19

Me metí de lleno en la Etapa 1, q es la revisión de literatura. Junté como
120 fuentes y las organicé en 4 ejes: Root of Trust y aislamiento en RISC-V,
Secure Boot bare-metal, attestation en tiempo de ejecución, y contadores de
hardware con machine learning.

Lo más importante q salió de acá: la afirmación q puse en el anteproyecto
sobre q "nadie ha hecho esto" está muy amplia y hay q recortarla. Sí hay
trabajos parecidos, como CHARM, LightFAt, LightFAt+ y un preprint que se
llama HPCCFA. Lo que sí sigue libre es la combinación específica de lo mío:
RISC-V bare-metal, con el clasificador corriendo adentro del Root of Trust,
y usando eventos arquitecturales en vez de microarquitecturales.

Mejor darme cuenta ahora que en la defensa.

### Miércoles 20

Hablé con el profe González, q es mi contraparte. Salieron varias cosas:

- El machine learning se queda. Él me había sugerido quitarlo xq en su
  experiencia lo difícil fue recolectar los datos, pero eso le pasó xq
  siempre había ruido del sistema operativo. En mi caso es bare-metal,
  entonces ese problema no lo tengo.
- Me sugirió usar series de tiempo en vez de promedios por corrida. Él usa
  promedios en su trabajo. Me pareció buena idea xq gano info sin tener que
  meter más contadores.
- Lo de probar en la tarjeta RISC-V queda para el final y solo si me da
  tiempo. Quedamos en q con correr un benchmark y comparar contra la
  emulación ya sirve para el paper.
- Me dijo q modelar los contadores en QEMU sí cuenta como aporte.

También me consiguió 4 papers q no podía bajar con el acceso del TEC. Los
leí y esto es lo q saqué:

- **ISQED 2019** (secure boot para RISC-V): usan firma asimétrica, ECDSA con
  SHA-3. Esto me sirve xq confirma q el enfoque del OE1 es el correcto. La
  diferencia es q ellos lo hacen con un bloque de hardware dedicado y yo lo
  voy a hacer en software puro en M-mode.
- **CHARM** (ACM TECS 2023): usan contadores en el dispositivo pero el
  clasificador lo corren del lado del verificador. Confirma la diferencia
  con lo mío, q el modelo va adentro.
- **TIFS 2020**: marco matemático de qué tan segura es la detección con
  contadores. Me sirve como respuesta a las críticas de Das 2019 y Zhou
  2018, q son lo más fuerte q hay en contra de usar contadores.
- **DATE 2021** (fTPM en RISC-V): resultó q es solo una propuesta de diseño
  y encima depende de OP-TEE con sistema operativo. O sea que mi plataforma
  está bastante más adelante de lo q pensaba.

### Jueves 21

Día de volver a tocar el código después de casi 3 meses.

Compilé el firmware y salió bien de una, los 16 objetos sin errores. Lo q
no estaba era qemu-ccore, así q lo tuve q compilar desde cero en esta
máquina. Tardó como media hora.

Corrí todo y **pasaron las 35 pruebas**. Todo sigue funcionando igual q en
junio: el aislamiento por PMP bloquea los accesos desde U-mode, el sellado
con AES anda, el quote firma bien, la cadena de suministro detecta
componentes alterados.

**Dos datos q tenía mal y hay q corregir:**

| Qué | Lo q tenía puesto | Lo q mide de verdad |
|---|---|---|
| Tiempo de arranque | 8.2 ms o 11 ms | **13.54 ms** |
| Versión de qemu-ccore | 8.2.2 | **10.2.94** |

Lo del tiempo igual está lejísimos del límite de 500 ms, así q el requisito
se cumple sin problema. De hecho me quedan como 486 ms de margen, o sea q
meterle la verificación de firma en el OE1 no me va a dar problema por ahí.

Lo de la versión de QEMU sí hay q arreglarlo en el anteproyecto y en el
paper xq está mal en los dos.

**Revisé el PMU de qemu-ccore** para ver con qué contadores cuento. Abrí
`target/riscv/pmu.c` y solo hay 5 eventos definidos:

- `HW_CPU_CYCLES` y `HW_INSTRUCTIONS`: estos sí cuentan, pero los aproxima
  desde el reloj de la máquina host, no los simula de verdad
- Los 3 de TLB: están declarados pero no tienen lógica q los incremente,
  o sea q están ahí de adorno

**Ninguno de los 4 contadores q necesito para el OE2 existe.** Ni accesos a
memoria, ni saltos indirectos, ni traps, ni cambios de modo. Los tengo q
hacer yo. Eso no es un problema xq es justo lo q dice el objetivo, pero es
más trabajo del q pensaba y ahora sé de dónde arranco.

**Algo q noté y me sirve para el OE3:** los tiempos de respuesta de los
comandos varían bastante, entre 432 y 771 microsegundos para la misma
operación con los mismos datos. Casi el doble. Eso viene de q el timer de
QEMU es aproximado. Lo bueno es q los contadores q voy a hacer en el OE2 no
van a tener ese problema, xq los voy a incrementar yo en el TCG cada vez q
pasa el evento. Van a ser exactos. Ese contraste me sirve de argumento para
el informe.

Otra cosa: el Secure Storage guarda el estado entre corridas, entonces el
contador NV arranca en 3 y no en 0, y algunos tests reportan rollback
cuando esperaban incrementar. No es un bug, es q ya venía de antes. Pero
para el OE4 voy a necesitar corridas limpias, así q tengo q hacer una forma
de resetear eso antes de medir.

Por último creé la rama `tfg` desde el commit 014752a, q es donde quedó
CE-1114. Así queda claro q es del curso pasado y qué es del TFG. La subí a
GitHub y a GitLab. También limpié el .gitignore xq tenía cosas repetidas y
me estaban quedando logs sueltos.

