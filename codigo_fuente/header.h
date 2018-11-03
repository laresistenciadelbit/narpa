#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include "packet32.h"
#include "winpcap_common.h"
#include "winarp_sk.h"
#include "getopt.h"
#include "Ntddndis.h"

#define TIEMPO_MSG		1000 //tiempo de espera entre mensajes		  (milisegundos/ms)
#define TIEMPO_PKT		100  //tiempo de espera de envio de paquetes  (milisegundos/ms)

#define TIEMPO_ATK		15 //tiempo de espera a paquete atacante (seg)
#define TIEMPO_ESCANEO	10 //tiempo de escaneo cada * min

#define MAC_FALSA		"00-FF-AA-BB-CC-FF"
#define ESPERA_ATK		3 //veces que espera a un ataque y si no llega vuelve a escanear las ips 
							// \_Tambien son las veces que espera al atacante multiplicado por 5
//		\_ con 3:  75 segs aprox en renovar ips cuando encuentre atacante despues de no haberlo encontrado hasta entonces.
//		\_ con 3:  45  segs  aprox en renovar ips si no encuentra ataque de un atacante ya focalizado

//*El tiempo es mayor que el aproximado dado a que cuando recibe un arp 
// reply del router el tiempo de espera en el bucle a ese paquete vuelve a empezar

//*No debe de ser menor que 3 ya que significaría que esperaría menos de lo que
//tarda en realizarse un ataque (poner un 2 significaría una espera de 30 segundos
//que es justo la media de espera entre ataques)