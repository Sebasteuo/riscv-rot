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

### Jueves 21 (parte 2, ya de madrugada)

Arranqué el OE2 en serio. Primero armé el documento de selección de
contadores, xq no quería ponerme a instrumentar sin saber qué iba a contar
ni por qué.

Quedaron 6 contadores en el núcleo mínimo: cargas, almacenamientos, saltos
tomados, saltos indirectos, traps y cambios de modo. Puse 6 y no 4 xq el
paper de TIFS dice q con 4 la probabilidad de q un atacante los iguale cae
bajo e⁻⁴⁰, o sea q 4 es el piso, no la meta. Y González ya me había avisado
q 4 podían no alcanzar.

El más importante de todos es el de saltos indirectos (`jalr`), xq ahí están
los retornos y las llamadas por puntero, q es justo lo q secuestra un ataque
de flujo de control. NumChecker y ConFirm lo confirman.

**Lo mejor del día:** revisando `riscv_pmu_incr_ctr()` en `pmu.c` me di
cuenta de q ya trae hechas 3 cosas q yo pensaba q iba a tener q construir:

1. El filtrado por modo de privilegio (los bits MINH, SINH, UINH). O sea q
   puedo contar solo lo de U-mode y excluir mi propio crypto core. Eso es
   justo lo q el SoK de Das dice q falta en los sistemas reales.
2. El manejo de desbordamiento con interrupción, q es lo q necesito para el
   muestreo por eventos del OE3.
3. El mapeo dinámico de evento a contador.

Entonces mi trabajo se reduce a definir los eventos y llamar a esa función
desde los lugares correctos. Bastante menos de lo q pensaba.

**Lo q hice:**

- Definí los 6 eventos en el rango 0xF0-0xF5, q queda fuera de la
  codificación SBI. El manual privilegiado dice q los selectores son WARL y
  definidos por la plataforma, así q meter eventos propios va con la
  especificación, no es un parche.
- Los agregué al switch de validación en `pmu.c`, xq si no el firmware no
  los podía mapear.
- Instrumenté 2: `PRIV_SWITCH` dentro del if q ya detecta el cambio real de
  modo en `riscv_cpu_set_mode`, y `TRAP_TAKEN` al inicio de
  `riscv_cpu_do_interrupt`.
- Del lado del firmware hice `src/hpm.c` y `include/hpm.h` para mapear los
  eventos a contadores físicos y leerlos.

Empecé por esos 2 a propósito, xq se instrumentan en funciones C q ya
existen. Los otros 4 hay q meterlos en la traducción de instrucciones, q es
más delicado.

**Primera medición:**

PRIV_SWITCH = 268
TRAP_TAKEN = 134


**268 es exactamente el doble de 134.** Eso no es casualidad: cada trap
genera 2 transiciones de privilegio, una entrando a M-mode y otra volviendo
a U-mode. O sea q los contadores no solo cuentan algo, cuentan lo correcto y
son consistentes entre sí. Buena forma de validar q la instrumentación quedó
bien.

También abrí la rama `tfg-counters` en qemu-ccore para q los cambios míos
queden separados del fork.

### Viernes 22

Terminé de instrumentar los 6 contadores del núcleo mínimo. Quedaron todos.

**Lo primero fue entender un problema q no tenía ayer.** Los 2 de ayer los
puse en funciones C normales, o sea q se ejecutan cada vez q pasa el evento.
Pero cargas, almacenamientos y saltos se traducen, y el traductor de QEMU
corre UNA sola vez y después el código traducido se reutiliza miles de
veces. Si ponía el incremento ahí directo iba a contar cuántas veces se
tradujo la instrucción, no cuántas veces se ejecutó. Habría dado números q
parecen razonables pero están mal.

La solución fue hacer un helper: el traductor genera código q, en tiempo de
ejecución, llama a una función C q incrementa el contador. Eso sí cuenta
ejecuciones reales.

**Lo bueno es q había 3 puntos centrales** por donde pasa todo:
`gen_load` cubre lb, lh, lw, ld y las variantes sin signo. `gen_store` cubre
sb, sh, sw, sd. Y `trans_jalr` los saltos indirectos. Con 3 ediciones cubrí
las 3 familias completas.

El de saltos condicionales fue distinto xq la instrucción se ejecuta siempre
pero el salto se toma o no según la comparación. Si lo ponía al inicio iba a
contar TODOS los saltos ejecutados, no los tomados. Por suerte QEMU tiene el
código comentado: hay un `gen_set_label(l); /* branch taken */` y ahí es
donde va, después de la etiqueta.

**Los 6 contadores midiendo:**

PRIV_SWITCH         268
TRAP_TAKEN          134
LOAD_RETIRED    1102856
STORE_RETIRED    526736
JUMP_INDIRECT     52387
BRANCH_TAKEN     142537

Las cargas son como el doble de los almacenamientos, q es lo q se espera de
código compilado con -O0. Si hubiera salido al revés algo estaría mal.

### El experimento de varianza, q fue lo mejor del día

Corrí el mismo binario 10 veces desde cero y comparé. `PRIV_SWITCH` y
`TRAP_TAKEN` dieron **exactamente lo mismo las 10 veces**. Los otros 4
variaron, pero poquísimo, todo por debajo del 0.011%.

Lo raro fue q la variación estaba **cuantizada**. Los valores de
LOAD_RETIRED eran 1102834, 1102856, 1102878, 1102900. Las diferencias:
22, 22, 22. Siempre el mismo paso. Y los 4 contadores se movían juntos.

Eso no es ruido aleatorio, es el programa ejecutando un bloque completo una
vez más o una vez menos. Entonces me puse a buscar cuál era.

Primero pensé q era el bucle del lockout, pero conté las iteraciones y son
2 en las 10 corridas. Estable. Hipótesis descartada.

**El culpable resultó ser `uart_put_dec`.** El firmware imprime tiempos con
`timer_report` en cada comando, y esos tiempos cambian entre corridas xq el
timer de QEMU se aproxima desde el reloj del host. Cuando un tiempo tiene un
dígito más, `uart_put_dec` hace una división más en su bucle. Con -O0 eso
cuesta exactamente 22 cargas.

Lo comprobé contando el total de dígitos impresos en cada corrida:

| Dígitos | LOAD_RETIRED |
|---|---|
| 165 | 1102834 |
| 166 | 1102856 |
| 167 | 1102878 |

Correlación perfecta. Un dígito = 22 cargas, 18 almacenamientos, 2 saltos
indirectos y 4 saltos tomados. Siempre.

**Por q esto importa tanto:** el SoK de Das (IEEE S&P 2019) es la crítica más
fuerte q existe contra usar contadores para seguridad, y lista 4 problemas:
no determinismo, sobreconteo, contaminación entre procesos y pérdida en
cambios de contexto. Ahora puedo decir con datos propios q **ninguno de los
4 aplica** en mi plataforma. Y no puedo decir solo "varía poco", puedo decir
q toda la variación se explica por trabajo realmente ejecutado y no por
error de medición. Eso es cualitativamente distinto.

Das además dice q los modelos q dependen de deltas del 1% al 5% colapsan por
error de medición. Yo estoy 2 órdenes de magnitud por debajo de ese piso.

Dejé el experimento como script en `tools/hpm_variance.py` para q sea
reproducible y no quede solo como una tabla en el informe.

**Falta para cerrar el OE2:** pruebas unitarias por contador (correr una
carga conocida y verificar q da el número esperado) y documentar el parche.

