/*
		<Proyecto NARPA>   (N)o (A)(R)(P) (A)ttacks

	Protege a una red de ataques arp contraatacando al atacante
	y devolviendo las tablas arp de la red a su cauce.

Copyright (C) 2009-2011

Este programa es software libre. Puede redistribuirlo y/o modificarlo bajo los términos de la
 Licencia Pública General de GNU según es publicada por la Free Software Foundation, bien de la 
versión 2 de dicha Licencia o bien (según su elección) de cualquier versión posterior.

Este programa se distribuye con la esperanza de que sea útil, pero SIN NINGUNA GARANTÍA, 
incluso sin la garantía MERCANTIL implícita o sin garantizar la CONVENIENCIA PARA UN 
PROPÓSITO PARTICULAR. Véase la Licencia Pública General de GNU para más detalles.

Debería haber recibido una copia de la Licencia Pública General junto con este programa. 
Si no ha sido así, lea <http:www.gnu.org/licenses/>.
*/

#include "header.h"

#define HOSTS 254

	char ipeq  [16]="";	//ip de este equipo
	char macaux[18]="";	//almacen auxiliar de mac

	bool primera_vez=TRUE;	 //controla acciones de primera vez(descubrir gw real, escribir arp estatico...)

void transformaU_a_ip(unsigned char ipini[4],char* ipfin);
void transforma_a_ipU (char* ipini,  unsigned char ipfin[4] );
int get_attack_mac(LPADAPTER lpAdapter, unsigned char *iptarget, unsigned char *remotemac, int mode, unsigned tiempo_esp=TIEMPO_ATK*1000);
void winarp_sk  (int argc, char *argVSK[], int interfaz=-1);
void help();


int main(int argc, char *argv[])
{
	int interfaz;
	char **argum;

	char ips   [HOSTS][16];	// ips de la red
	bool online[HOSTS];		// ips online
	char macs  [HOSTS][18]; //macs de la red

	char ipgw   [16]="";	//ip del gw/router
	char macgw  [18]="";	//mac del gw/router
	char ipatk  [16]="";	//ip del atacante
	char macatk [18]="";	//mac del atacante

	char bytegw='1'; //ultimo byte de ip del gw/router

	bool posible_gw=FALSE;	 //bool para entrar o no en condiciones cuando no se sabe cual es el gw real
	char posib_gw[2][18];	 //posible gateway (solo usado si primera_vez=TRUE)
	unsigned cuenta_p_gw[2]={0,0}; //veces que aparece esa mac en la lista de hosts (solo usado si primera_vez=TRUE)
	bool scan_seguro=FALSE;	 //realiza un escaneo de los hosts deshechando los paquetes con mac del atacante.
	unsigned cuenta_mac_falsas=0; //cuenta el nº de hosts con la mac del atacante.

	unsigned char	ipunsigned [ARP_IP_ADD_SPACE];
	
	LPADAPTER adaptador = 0;
	unsigned bytei=0,macatacada,contraataques=0;
	unsigned ataqueoffline=0; //ataqueoffline es contador de si no hay ataques en la red (aumenta cada 15 seg)
	bool spoof=FALSE,arp_reply_activo=FALSE,encontro_atk=FALSE;
	system("color 0a");

	switch(argc)	//sacamos interfaz de los argumentos y los regulamos
	{
		case 1:{
			argc=3; argv[1]="-i"; argv[2]="33";interfaz=atoi(argv[2]);	
			break;
		}
		case 3:{
			if (argv[1][0]=='-' || argv[1][0]=='/')
			{
				if(argv[1][1]=='i' )
				{
					if(argv[2][0]=='-') interfaz=-1;
					else interfaz=atoi(argv[2]);
				}else if (argv[1][1]=='g' ){
					interfaz=33;
				}
			}else{
				printf("\n**Error de argumentos\n");return(1);
			}
			break;
		}
		case 5:{
			if ( (argv[1][0]=='-' || argv[1][0]=='/') && (argv[3][0]=='-' || argv[3][0]=='/') )
			{
				if(argv[1][1]=='i' )
				{
					if(argv[2][0]=='-') interfaz=-1;
					else interfaz=atoi(argv[2]);
				}else if (argv[1][1]=='g' && argv[3][1]=='i' ){
					if(argv[4][0]=='-') interfaz=-1;
					else interfaz=atoi(argv[4]);
					}else{
					printf("\n**Error de argumentos\n");return(1);}
			}else{
				printf("\n**Error de argumentos\n");return(1);
			}
			break;
		}
		default:
			if(argc>1 && !( argv[1][0] == '-' || argv[1][0] == '/' ) )
			{help();return 0;}
	}

	switch(argv[1][1])
	{
		case 'a':{
			if( open_adapter(0,-1) == EXIT_FAILURE ) return 1;
			break;
		}

		case 'g':
		case 'i':
		{

			printf("\n\n    \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_____________________________//////////////////");
			printf("\n     \\\\                                                          //");
			printf("\n     // NARPA   <-- (N)o  (A)(R)(P)  (A)ttacks --> V_%s by Neru \\\\ \n", RELEASE_VERSION);
			printf("     \\\\____________________based on winarp_sk____________________// \n\n");

			
		// * Valida argumentos * /
			if( argc==3 || argc==5 )
			{

			// * Recoge ip local * /
				get_ip_addr(NULL);
				printf("\n\t[+]IP local      : %s\n",ipeq);
				Sleep(TIEMPO_MSG);

			// * Genera ip gw/router * /
			if(argc==5 || (argc==3 && argv[1][1]=='g') )//si se le indicó el gw/router
			{
				if (argv[1][1]=='g') strcpy(ipgw,argv[2]);
				else strcpy(ipgw,argv[4]);
			}else{
				for(unsigned punto=0; punto!=3; bytei++)
				{
					if(	ipeq[bytei]!='.' ) ipgw[bytei]=ipeq[bytei];
					else
					{
						ipgw[bytei]='.';
						punto++;
					}
				}
				ipgw[bytei]=bytegw; //ultimo byte de ip del gw/router
				ipgw[bytei+1]='\0';
			}
				printf("\n\t[+]IP  router/gw : %s",ipgw);



			// * Recoge mac del gateway * /
				/**/if(interfaz==33){interfaz=open_adapter(&adaptador,interfaz);close_adapter(adaptador);} //si no le hemos asignado interfaz, usa la mas alta.
					if( open_adapter(&adaptador,interfaz) == EXIT_FAILURE ) return 1;
					transforma_a_ipU(ipgw, ipunsigned);
					if( get_remote_mac(adaptador, ipunsigned, NULL, 1) == EXIT_FAILURE)
						if( get_remote_mac(adaptador, ipunsigned, NULL, 1) == EXIT_FAILURE)	return 1;

					strcpy(posib_gw[0],macaux);

					//Tras coger el primer paquete, ahora nos cercioraremos de si este paquete es de un atacante
					//o si el atacante responde después (ambos casos pueden suceder según sea una red wireless o por cable)
					
					for(unsigned i=0; i<8; i++)	//esperamos 8 paquetes como máximo si el atacante esta respondiendo mentiras
					{
						if(i>0)
						{
							if(strcmp(posib_gw[0],macaux)==0)//si es igual al anterior
							{
								get_attack_mac(adaptador, ipunsigned, NULL, 1, 400);
							}
							else
							{
								strcpy(posib_gw[1],macaux);
								posible_gw=TRUE;
								break;
							}
						}
						else get_attack_mac(adaptador, ipunsigned, NULL, 1, 400);
					}
					
					if(!posible_gw) strcpy(macgw,macaux);	//si SOLAMENTE ha respondido una o varias veces la MISMA dirección mac, esa es el gw
				/**/close_adapter(adaptador);


				if(!posible_gw)printf("\n\t[+]MAC router/gw : %s\n\n\n\t** La red no esta siendo atacada por el momento **",macgw);
				else printf("\n\n\t\t**  Hay un ataque en la red  **\n\n\n\t[+]Descubriendo MAC del router/gw ...");
				Sleep(TIEMPO_MSG);



	do{

			// * Recoge la lista de hosts y macs asociadas * /
				printf("\n\n\n [+]Almacenando hosts... (mac, ip y estado)\n");
				Sleep(4500);

				//reiniciamos variables de break/continue:
				cuenta_mac_falsas=0;
				ataqueoffline=0;

				for(unsigned h=1; h<=HOSTS; h++)
				{
					ipunsigned[3]=h;
					if(primera_vez) transformaU_a_ip(ipunsigned,ips[h]);//almacena la ip

					if(strcmp(ips[h],ipeq)==0)	//si es nuestra IP
					{
						printf("\n\t* %s online  <IP LOCAL>",ips[h]);
						online[h]=FALSE; //la marca como inactiva
					}
					else
					{
					/**/if( open_adapter(&adaptador,interfaz) == EXIT_FAILURE ) return 1;

						if( get_remote_mac(adaptador, ipunsigned, NULL, 1) == EXIT_FAILURE)
						{	 //pone un flag de online (0)
							online[h]=FALSE;		
						}
						else // si está *ONLINE* almacena la mac de esta ip y pone flag de online (1)
						{
							if(scan_seguro)	//este escaneo se basa en recibir los paquetes y descartar los del atacante
							{
								if( strcmp(macatk,macaux)==0 )
								{
									for(unsigned i=0; i<5; i++)	//esperamos 5 paquetes <como máximo> si el atacante esta respondiendo mentiras
									{
										if(i>0)
										{
											if(strcmp(macatk,macaux)==0)
											{
												get_attack_mac(adaptador, ipunsigned, NULL, 1, 200);
											}
											else break; //encontró la real!
										}
										else get_attack_mac(adaptador, ipunsigned, NULL, 1, 200);
									}
								}//sino esque es la real (se sale del if)
							}
						
							strcpy(macs[h],macaux);
							online[h]=TRUE;
							printf("\t* %s   mac   %s",ips[h],macs[h]);

							if(primera_vez && posible_gw && strcmp(ips[h],ipgw)!=0)
							{
								if (strcmp(posib_gw[0],macs[h])==0) cuenta_p_gw[0]++;
								if (strcmp(posib_gw[1],macs[h])==0) cuenta_p_gw[1]++;
								if(cuenta_p_gw[0]>=2 || cuenta_p_gw[1]>=2) break; //si se encontró atacante falseando macs
							}
							if( !primera_vez && strcmp(ips[h],ipgw)!=0 && strcmp(macatk,macs[h])==0 )//solo entra aquí si se encontró un ataque con anterioridad
							{
								cuenta_mac_falsas++;
								if( cuenta_mac_falsas>1 ) break;
							}
							if( primera_vez && !posible_gw && strcmp(ips[h],ipgw)!=0 && strcmp(macs[h],macgw)==0 )//DoS o mala redireccion
							{
								cuenta_mac_falsas++;
								if(cuenta_mac_falsas>1)break;
								strcpy(macatk,macs[h]);
								encontro_atk=TRUE;
							}
						}

					/**/close_adapter(adaptador);
					}
				}



			// * FIN DE ESCANEO: Validación de spoofing * /
				
				//obtenemos mac del atacante y gw con el anterior escaneo y rescanea en modo seguro si hubo spoof en las otras ips
				if (posible_gw && cuenta_p_gw[0]>0)
				{
					strcpy(macatk,posib_gw[0]);
					strcpy(macgw, posib_gw[1]);
					encontro_atk=TRUE;

					if(cuenta_p_gw[0]>1)
					{
						scan_seguro=TRUE;
						printf("\n\n  * Direcciones mac spoofeadas, se realizara un escaneo en modo seguro *\n");
						//continue;
					}
					printf("\n\n\n\t[-]MAC router/gw descubierta : %s\n",macgw);
				}
				if (posible_gw && cuenta_p_gw[1]>0)
				{
					strcpy(macgw, posib_gw[0]);
					strcpy(macatk,posib_gw[1]);
					encontro_atk=TRUE;

					if(cuenta_p_gw[1]>1)
					{
						scan_seguro=TRUE;
						printf("\n\n  * Direcciones mac spoofeadas, se realizara un escaneo en modo seguro *\n");
						//continue;
					}
					printf("\n\t[+]MAC router/gw descubierta : %s\n",macgw);
				}
				
				//si se hizo spoof sobre las otras ips se realiza escaneo seguro
				if(cuenta_mac_falsas>1 && !primera_vez)
				{
					//cuenta_mac_falsas=0;
					scan_seguro=TRUE;
					printf("\n\n  * Direcciones mac spoofeadas, se realizara un escaneo en modo seguro *\n");
					//continue;
				}

				//si se hizo spoof sobre las otras ips pero no recibimos la mac real del gw sólo la atacante y por lo tanto narpa pensó que esa era la real del gw
				if(cuenta_mac_falsas>1 && primera_vez)	//(el tráfico no está bien redirecionado o es un ataque DoS)
				{
					printf("\n\n  * El atacante esta realizando un ataque DoS sobre la red o\n  no esta redireccionando a los hosts victimas  *\n");
					printf("\n   [+]Introduzca la mac del gateway manualmente para proteger la red");
					
					bool errorinput=FALSE;//solo se usara una vez ,asi q no pasa nada por declararla aquí
					do{
						if(errorinput)
						{
							printf("\n\n\t* Formato de mac erroneo. Ej: 00-AA-00-55-00-FF  *");
							errorinput=false;
						}
						printf("\n\t[-]Mac gateway: ");
						fgets (macaux, strlen("00-00-00-00-00-00")+2, stdin);
						fflush(stdin);
						macaux[strlen(macaux)-1]='\0';
						for(unsigned i=0; i<strlen("00-00-00-00-00-00"); i++)
						{
							if(i==2 || i==5 || i==8 || i==11 || i==14)
							{
								if(macaux[i]!='-')
								{
									errorinput=true;
									break;
								}
							}
							else
							{
								if( !(macaux[i] >= '0' && macaux[i] <= '9') && !(macaux[i]>='A' && macaux[i]<='F') )
								{
									errorinput=true;
									break;
								}
							}
						}

					}while(errorinput);

					strcpy(macgw,macaux);//aqui tenemos ya macatk y macgw

					//cuenta_mac_falsas=0;
					scan_seguro=TRUE;
					//continue;
				}

			// * Fin de validacion * /


			if(primera_vez)
			{

			// * Añade la mac del router que acaba de descubrir a la tabla arp de forma estática * /
				char* comando;
				comando = new char [strlen("arp.exe -s ")+strlen(ipgw)+ 1 +strlen(macgw)+1];
				strcpy(comando,"arp.exe -s ");
				strcat(comando,ipgw);
				strcat(comando," ");
				strcat(comando,macgw);
				if(system(comando)==EXIT_FAILURE) printf("\n\n\t\t**FALLO AL INTENTAR ESCRIBIR LA ENTRADA ARP**");
				else printf("\n\n\n\n\t   [-]Entrada estatica escrita en la tabla arp\n\n");
				delete comando;
				Sleep(TIEMPO_MSG);


			// * Reservamos espacio a argumentos de winarp_sk (si no ha pasado por aqui)* /
				//-S no se usa porque no funciona el spoof de mac contra winXP

				argum= new char *[12];//maximo: [12] argumentos; 
				argum[0]=argv[0];
				argum[1]= new char [2];//ej: "-m"
				argum[2]= new char [1];//ej: "1","2"

				argum[3]= new char [2];//ej: "-D"
				argum[4]= new char [18];//ej: "ff-ff-ff-ff-ff-ff"
				argum[5]= new char [2];//ej: "-F"
				argum[6]= new char [18];//ej: "ff-ff-ff-ff-ff-ff"
				argum[7]= new char [2];//ej: "-T"
				argum[8]= new char [18];//ej: "ff-ff-ff-ff-ff-ff"

				argum[9]= new char [2];//ej: "-s"
				argum[10]= new char [18];//ej: "192.168.0.20"
				argum[11]= new char [2];//ej: "-d"
				argum[12]= new char [18];//ej: "192.168.0.1"

				// D:4  -  F:6  -  T:8  -  s:10  -  d:12
			}



			posible_gw=FALSE; //desactiva el flag de buscar el gw real porque ya la tenemos y ya la hemos escrito en la tabla arp estáticamente
			primera_vez=FALSE;	//indicamos que ya hemos estado por primera vez en toda esta zona
								//para que no vuelva a reservar memoria ni a escribir el arp estático, etc.

			if(!primera_vez && cuenta_mac_falsas==0)	scan_seguro=FALSE;

			if(scan_seguro)	continue;
			scan_seguro=FALSE;



			if(!encontro_atk)//si aun no tiene el atacante lo busca
			{
			// * Busca el atacante en la red * /
				printf("\n\n\t[+]En espera de ataques en la red...\n");
					transforma_a_ipU(ipgw, ipunsigned);
					strcpy(macaux,"");
					do{
						//if(ataqueoffline>ESPERA_ATK*5) break;//comentado: no se sale del bucle, se espera a encontrar atacante para escanear hosts
						if( open_adapter(&adaptador,interfaz) == EXIT_FAILURE ) return 1;
							macatacada=get_attack_mac(adaptador, ipunsigned, NULL, 1);
						close_adapter(adaptador);
						printf("\n");
						if(macatacada==EXIT_FAILURE) return 1;
						if(strcmp(macgw,macaux) == 0 && macatacada==0) printf("[-] Respuesta ARP del gw %s",ipgw);
						if(strcmp(macgw,macaux) != 0 || macatacada!=0 ) ataqueoffline++;	//si no recibe respuesta y no recibe arp del gw aumenta ataqueoffline
					}while( macatacada!=0 || strcmp(macgw,macaux) == 0 ); //mientras no encuentre ataque o reciba arp del gw: sigue esperando

				if(ataqueoffline>ESPERA_ATK*5)//se vuelven a escanear los hosts al encontrar el nuevo atacante y haber acabado el tiempo de espera
				{
					printf("\n\n\t*Se encontro atacante fuera de tiempo de espera\n");
					//ataqueoffline=0;
					continue;
				}
				//ataqueoffline=0;

				strcpy(macatk,macaux);

			}
			encontro_atk=FALSE;


				printf("\n\n\t\t[*]MAC ATACANTE: %s",macatk);
				Sleep(TIEMPO_MSG);
								
				for(unsigned h=2; h<=HOSTS; h++)
				{
					if ( online[h]==TRUE && (strcmp(macs[h],macatk)==0) )
					{
						strcpy(ipatk,ips[h]);
						break;
					}
					if(h==HOSTS) spoof=TRUE;
				}

				if(spoof)
				{
					printf("\n\t\t[*]IP  del atacante no encontrada o spoofeada!");
					spoof=FALSE;
					continue;
				}
				else		printf("\n\t\t[*]IP  ATACANTE: %s\n",ipatk);
				Sleep(TIEMPO_MSG);



			
				// * Preparamos los parámetros de winarp_sk: * /
					strcpy(argum[1],"-m");
					strcpy(argum[2],"1");
					
			
			printf("\n\n  ** Protegiendo a hosts, gateway y falseando al atacante **\n");


		while(1==1)	//5.4. Actualiza la caché arp de los pasos 5.1, 5.2 y 5.3 (una vez) (arp_reply_activo==TRUE)
		{
			ataqueoffline=0; //reiniciamos la variable

			// * Preparamos los restantes parametros dentro del bucle * /
				strcpy(argum[3],"-D");//Mac destino
				strcpy(argum[4],macgw);
				strcpy(argum[5],"-F");//Mac falsa
				//strcpy(argum[6],macgw);
				strcpy(argum[7],"-T");//00 en request,  mac dest en reply
				strcpy(argum[8],"00-00-00-00-00-00");

				strcpy(argum[9],"-s");//ip de la que engañamos
				//strcpy(argum[10],ipgw);
				strcpy(argum[11],"-d");//ip a la que engañamos
				strcpy(argum[12],ipgw);



			//Mi idea de contraataque era manchar sus tablas arp, pero resultó que el atacante no se
			//comunica usando su tabla arp sino que mantiene guardadas las direcciones mac dentro
			//de variables del programa atacante (cain,ettercap...)

			//Con lo que, esperamos a que intenten manchar nuestra tabla arp (lo hacen cada 30 segs)
			//y será cuando protegeremos al instante a los hosts de la red dandoles las macs reales contrarestando su ataque.



			if(contraataques < 1 || contraataques > 3) //despues de mandar los arp request manda arp replys directamente
			{
				strcpy(macaux,"");
				ipunsigned[3]=bytegw-48;

				do{							//si no recibe ataques en las proximas escuchas vuelve a escanear las ips
					if(ataqueoffline>=ESPERA_ATK)	break;	//por si el atacante ya no está o por si cambio de ip
					printf("\n[-] Esperando ataque...");
					if( open_adapter(&adaptador,interfaz) == EXIT_FAILURE ) return 1;
						macatacada=get_attack_mac(adaptador, ipunsigned, NULL, 1);
					close_adapter(adaptador);
					if(macatacada==EXIT_FAILURE) return 1;
					if( strcmp(macgw,macaux) == 0 && macatacada==0 ) printf("\n[-] Respuesta ARP del gw %s",ipgw);
					if( strcmp(macgw,macaux) != 0 || macatacada!=0 ) ataqueoffline++;	//si no recibe respuesta y no recibe arp del gw aumenta ataqueoffline
				}while( strcmp(macgw,macaux) == 0 || macatacada!=0 ); //mientras no encuentre ataque o responda el gw real: sigue esperando
				
			}
			else Sleep(300*contraataques);

			if(ataqueoffline>=ESPERA_ATK)//se vuelven a escanear los hosts al pasar el tiempo de espera de ataque (deben ser 45seg no menor) (numero:3)
			{
				ataqueoffline=0;
				break;
			}
			ataqueoffline=0;

			if(!arp_reply_activo)
			{
				printf("\n\n\t[+]Contraataque arp request");
				Sleep(300);
			}



			// * 5.1. Envío de las macs reales de los hosts asociadas a su ip al gw * /

				if(arp_reply_activo)	strcpy(argum[8],macgw);

				for(unsigned h=2; h<HOSTS; h++)
				{
					if( online[h]==TRUE && (strcmp(ips[h],ipatk) !=0) )
					{
						strcpy(argum[6],macs[h]);
						strcpy(argum[10],ips[h]);
						winarp_sk( 13, argum, interfaz );
					}
				}
				printf("\n\t\t* Gateway %s protegido",ipgw);

			// * 5.2. Envio de la mac real del gateway a cada host de la red * /

				strcpy(argum[6],macgw);
				strcpy(argum[10],ipgw);

				for(unsigned h=2; h<HOSTS; h++)
				{
					if( online[h]==TRUE && (strcmp(ips[h],ipatk) !=0) )
					{
						if(arp_reply_activo==TRUE)	strcpy(argum[8],macs[h]);
						strcpy(argum[4] ,macs[h]);
						strcpy(argum[12],ips [h]);
						
						winarp_sk( 13, argum, interfaz );
						printf("\n\t\t* IP %s protegida",ips[h]);
					}
				}
				

			// * 5.3. Envio de macs falsas de las ips de la red hacia el atacante * /

				if(arp_reply_activo)	strcpy(argum[8],macatk);
				strcpy(argum[4],macatk);
				strcpy(argum[12],ipatk);
				strcpy(argum[6] ,MAC_FALSA);

				for(unsigned h=1; h<HOSTS; h++)
				{
					if(online[h]==TRUE && (strcmp(ips[h],ipatk) !=0) )
					{
						strcpy(argum[10],ips [h]);	
						winarp_sk( 13, argum, interfaz );
					}
				}
				strcpy(argum[10],ipeq);
				winarp_sk( 13, argum, interfaz );//mentimos sobre eq. local

				printf("\t\t* Atacante %s aislado\n",ipatk);


			if(contraataques*30>=TIEMPO_ESCANEO*60)//contrataques * 30seg(que es lo que suele tardar en envenenar la cache arp)
			{
				contraataques=0;
				arp_reply_activo=FALSE;
				continue;
			}
			
			if(!arp_reply_activo)
			{
				printf("\n\n\t[+]Contraataque arp reply (x3)");
				strcpy(argum[2],"2");
				arp_reply_activo=TRUE; //en la proxima pasada no volverá a hacer 3 veces el arp reply
			}
			contraataques++;
		}

	}while(1==1); // * 5.6 Reescaneo de la red quitando hosts que esten ofline * /


	
	
				if(!spoof)	delete argum;
			}else printf("\n\t **parametros incorrectos**");
			break;
		}
		case 'h':
		{
			help();
			break;
		}
		default: 
			printf("\n\t\t**parametro incorrecto**\n\n");
			help();
	}
	return 0;
}



void transforma_a_ipU(char* ipini, unsigned char ipfin[4]) //transforma ip strings a ip unsigned
{
	unsigned int tmpaddr[4];

	sscanf(ipini, "%d.%d.%d.%d", 
	&tmpaddr[0], &tmpaddr[1], &tmpaddr[2], &tmpaddr[3]);
	       
    for(unsigned i = 0; i < 4; i++) {
		ipfin[i] = (unsigned char)tmpaddr[i]; 
    }
}

void transformaU_a_ip(unsigned char ipini[4],char* ipfin) //transforma ip unsigned a ip string
{
	char tmpaddr[4];

	itoa(ipini[0],tmpaddr,10);
	strcpy(ipfin, tmpaddr);
	strcat(ipfin,".");
	itoa(ipini[1],tmpaddr,10);
	strcat(ipfin, tmpaddr);
	strcat(ipfin,".");
	itoa(ipini[2],tmpaddr,10);
	strcat(ipfin, tmpaddr);
	strcat(ipfin,".");
	itoa(ipini[3],tmpaddr,10);
	strcat(ipfin, tmpaddr);
}


void help()
{
	printf("\n\n    \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_____________________________//////////////////");
	printf("\n     \\\\                                                          //");
	printf("\n     // NARPA   <-- (N)o  (A)(R)(P)  (A)ttacks --> V_%s          \\\\ \n", RELEASE_VERSION);
	printf("     \\\\____________________based on winarp_sk____________________// \n");
	printf("\n\n\t Estre programa se encarga de proteger la red local ante ataques arp");
	printf("\n\tmintiendo al propio atacante y aislandolo de la red.");
	printf("\n\n\tNo es necesario especificar ningun argumento al programa,");
	printf("\n\n\tsin argumentos trabajara por defecto con la primera interfaz de red");
	printf("\n\n.\t.\t.\t.\t.\t.\t.\t.\t.\t.\n");
	printf("\n\t [-i  numero de interfaz] el numero lo visualizamos con el argumento -a\n");
	printf("\n\t [-a]  muestra las interfaces de red del equipo local\n");
	printf("\n\t [-g  ip] le damos la ip del gateway/router/proxy manualmente\n");
	printf("\n\t [-h]  muestra la ayuda\n");
	printf("\n");

}