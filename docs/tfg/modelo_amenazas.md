# Modelo de amenazas

**Etapa 1, punto 4** · TFG CE-5600 · Sebastián Alba Vives
22 de agosto de 2026

---

## 1. Para qué sirve este documento

Un modelo de amenazas dice tres cosas: qué estoy protegiendo, contra quién, y
qué queda deliberadamente fuera. Lo que queda fuera se declara, no se esconde.

El modelo del anteproyecto era preliminar. Acá lo refino con lo que salió de
la revisión de literatura y con lo que ya está medido en la plataforma.

---

## 2. Qué protejo

Ordenado por lo que se pierde si cae.

| # | Activo | Dónde vive | Si el atacante lo consigue |
|---|---|---|---|
| A1 | EK, la llave de identidad | Secure Storage, `0x10200000` | Puede hacerse pasar por el dispositivo. Toda la attestation deja de valer |
| A2 | SRK, la llave de almacenamiento | Secure Storage | Puede abrir todo lo sellado |
| A3 | Valores de los PCR | Región protegida, `0x80100000` | Puede fabricar evidencia de un arranque limpio |
| A4 | Contador anti-rollback | Secure Storage | Puede instalar firmware viejo con fallas conocidas |
| A5 | Stage-1 y su llave pública | ROM en hardware real, imagen separada acá | Se cae toda la cadena. Es la raíz |
| A6 | El modelo clasificador | Dentro del crypto core (OE3) | Puede estudiarlo para evadirlo |
| A7 | Los contadores | CSRs, leídos solo desde M-mode | Puede falsear la evidencia de comportamiento |

Los primeros cuatro ya están protegidos por la plataforma base. Los tres
últimos aparecen con el TFG.

---

## 3. Contra quién

### Dentro del alcance

**A1. Modificar el firmware con el equipo apagado.**
El atacante tiene acceso al medio de almacenamiento y puede reescribir la
imagen. Es el escenario clásico de firmware alterado.

**A2. Modificar el valor de referencia junto con el firmware.**
Esta es la que importa. El Secure Boot actual compara contra hashes guardados
en el mismo dispositivo, así que un atacante que cambie las dos cosas pasa la
verificación. **Es el hueco que cierra el OE1.**

**A3. Comprometer el sistema en U-mode mientras opera.**
Corrupción de memoria, inyección de código, secuestro de flujo de control. El
sistema arrancó limpio y se compromete después. **Es el hueco que cierra el OE3.**

**A4. Intentar leer o escribir los recursos del crypto core desde U-mode.**
Ya está cubierto por PMP y verificado con pruebas que lo intentan y reciben
excepción del procesador.

**A5. Mandar comandos arbitrarios o mal formados por el buzón.**
Códigos que no existen, tamaños fuera de rango, campos inconsistentes. Ya
está cubierto: comando desconocido devuelve error y no toca estado interno.

**A6. Evadir el clasificador moldeando el perfil de contadores.**
El atacante conoce el sistema y ajusta su ataque para que los conteos se
parezcan a lo normal. Dinakarrao y coautores (DAC 2019) demuestran que los
detectores basados en eventos son evadibles así. ConFirm (ICCAD 2015)
describe la versión concreta: si el atacante sabe dónde están los puntos de
medición, altera el flujo entre dos de ellos y compensa después para que la
suma cuadre.

**A7. Reutilizar un reporte de attestation viejo.**
El atacante guarda una respuesta de cuando el sistema estaba sano y la
reenvía después. Coker y coautores lo llaman el principio de frescura.

### Fuera del alcance, y por qué

**O1. Ataques físicos.** Sondeo, decapado, lectura directa de memoria. Fuera
del alcance de un trabajo sobre emulación.

**O2. Canales laterales.** Tiempo, consumo, caché. La plataforma no los
considera y el emulador no los modela con fidelidad.

**O3. Inyección de fallos.** Y esta hay que declararla con cuidado, porque
toca directamente al OE1. BADFET (WOOT 2017) y el trabajo sobre el ESP32-C3
(WOOT 2024) muestran que una verificación de firma correcta se puede evadir
saltándose la instrucción que consume el resultado. **La firma asimétrica
cierra la sustitución por software, no la inyección de fallos.** Conviene
decirlo explícito en vez de sobreafirmar.

**O4. Comprometer el emulador o la máquina anfitriona.** Si el atacante
controla QEMU, controla todo. Es el límite del entorno experimental.

**O5. Comprometer al propio Stage-1.** El modelo asume que Stage-1 es
inmutable. En hardware real eso se logra poniéndolo en ROM de máscara, que es
lo que hacen SMART, LIRA-V y OpenTitan. En este trabajo se declara como
supuesto porque el emulador no modela ROM real.

**O6. Robar la llave privada de firma.** Nunca entra al dispositivo. Vive
donde se compila el firmware.

**O7. Aliasing físico de memoria contra PMP.** Un trabajo reciente muestra un
ataque estilo BadRAM que evade el aislamiento por PMP mediante aliasing de
memoria física. Requiere capacidad de manipular el mapeo físico, o sea acceso
al hardware. Cae bajo O1, pero conviene nombrarlo porque es específico de PMP
y un lector informado podría preguntarlo.

---

## 4. Qué garantiza cada mecanismo

| Ataque | Mecanismo que lo cubre | Estado |
|---|---|---|
| A1, A2 | Secure Boot de dos etapas con firma Ed25519 | **OE1**, en desarrollo |
| A3 | Attestation en tiempo de ejecución con contadores | **OE2 y OE3** |
| A4 | Aislamiento por PMP, seis regiones sin comodín | Hecho y verificado |
| A5 | Validación de comandos en el buzón | Hecho y verificado |
| A6 | Aleatorización de puntos de medición | **OE3**, mitigación parcial |
| A7 | Desafío externo por el buzón | **OE3** |

---

## 5. Las propiedades que se reclaman

Conviene ser preciso con qué se afirma y con qué fuerza.

**P1. Confidencialidad de las llaves frente al software en U-mode.**
Garantía fuerte: la impone el procesador con PMP, no un programa. Verificado
con pruebas que intentan el acceso y reciben excepción.

**P2. Integridad de los PCR frente al software en U-mode.**
Garantía fuerte, mismo mecanismo.

**P3. Autenticidad del firmware que arranca.**
Garantía fuerte bajo el supuesto O5, o sea que Stage-1 sea inmutable. Sin ese
supuesto no hay raíz de confianza posible, y es el mismo supuesto que hacen
todos los trabajos del área.

**P4. Frescura de la evidencia de runtime.**
Garantía fuerte si el desafío viene de afuera. Por eso el diseño no genera su
propio desafío.

**P5. Detectabilidad de un compromiso en U-mode.**
**Garantía probabilística, no absoluta.** Esto hay que decirlo claro. El
clasificador detecta desviaciones del comportamiento aprendido, no
compromisos. Un ataque que reproduzca el perfil nominal no se detecta.

Basu y coautores (IEEE TIFS 2020) dan el marco cuantitativo: con cuatro
contadores monitoreados la probabilidad de que un atacante los iguale todos
cae por debajo de e⁻⁴⁰. Pero su modelo asume que el atacante no sabe cuáles
contadores se están observando. En este trabajo el conjunto de contadores es
público, así que esa garantía es más débil y conviene declararlo.

---

## 6. Lo que la plataforma ya demuestra

No son supuestos, son resultados medidos.

**El aislamiento funciona.** Cuatro de las 35 pruebas intentan violar PMP y
las cuatro reciben excepción del procesador: leer la zona secreta, escribirla,
leer el código del crypto core y leer el Secure Storage. Un quinto intento
escribe `pmpcfg0` desde U-mode y recibe instrucción ilegal.

**El buzón valida.** Un comando desconocido devuelve error sin tocar estado.

**Los contadores son deterministas.** Diez corridas del mismo binario: los
contadores de eventos discretos dan idéntico, los de instrucciones varían por
debajo del 0.011%, y esa variación se explica completamente por la cantidad de
dígitos que imprime el firmware. No es error de medición.

Ese último resultado responde de frente al SoK de Das y coautores (IEEE S&P
2019), que es la crítica más fuerte contra usar contadores para seguridad.
Sus cuatro problemas son no determinismo, sobreconteo, contaminación entre
procesos y pérdida en cambios de contexto. Los dos últimos no aplican porque
no hay planificador ni cambios de contexto. Los dos primeros están acotados
experimentalmente.

---

## 7. Lo que queda abierto

- La evasión adversarial (A6) se mitiga parcialmente, no se resuelve. Hay que
  reportarlo como limitación, no como problema resuelto.
- El supuesto de Stage-1 inmutable (O5) es indemostrable en emulación. Se
  declara y se justifica con la práctica del área.
- La inyección de fallos (O3) queda fuera y hay que decirlo al reportar el
  OE1, para no sobreafirmar lo que da la firma asimétrica.
