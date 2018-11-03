#include <string.h>

#include <stdio.h>
#include "packet32.h"
#include "winpcap_common.h"


int open_adapter(LPADAPTER *lpAdapter, int interfaz) 
{
  /* ASCII strings for WIN9x */
  char  AdapterNameA[ADAPTER_NAMES_SIZE];
  char  *TmpAdapterA;
  char  *AnotherTmpAdapterA; 
  
  /* UNICODE strings for WINNT */
  char  AdapterNameU[ADAPTER_NAMES_SIZE];
  char  *TmpAdapterU;
  char  *AnotherTmpAdapterU; 
  
  /* Others */
  char  AdapterList[MAX_ADAPTER_NUM][ADAPTER_NAMES_SIZE];
  int   AdapterNum;
  int   i = 0;
  //int   SelectedAdapter;
  ULONG AdapterLength = ADAPTER_NAMES_SIZE;
  DWORD Version;
  DWORD WindowsMajorVersion;


  /* List adapter names */
  if(interfaz <1) 
  {
	  printf("\nInterfaces instaladas :\n");
  }

  /* Get operating system version */
  Version = GetVersion();
  WindowsMajorVersion = (DWORD)(LOBYTE(LOWORD(Version)));

  /* Get adapter names */
  if(!(Version >= 0x80000000 && WindowsMajorVersion >= 4)) {
    // Windows NT
    if(PacketGetAdapterNames(AdapterNameU, &AdapterLength) == FALSE) {
	  if(interfaz <1)  printf("No fue posible leer la lista de adaptadores de red!\n");
      return(EXIT_FAILURE);
    }

    TmpAdapterU = AdapterNameU;
    AnotherTmpAdapterU = AdapterNameU;

	
    while((*TmpAdapterU != '\0') || (*(TmpAdapterU - 1) != '\0')) {
      if(*TmpAdapterU == '\0') {
        memcpy(AdapterList[i], AnotherTmpAdapterU, (TmpAdapterU - AnotherTmpAdapterU ) * 2);
		AdapterList[i][(TmpAdapterU - AnotherTmpAdapterU ) * 2] = '\0';
        AnotherTmpAdapterU = TmpAdapterU + 1;
        i++;
      }
				
      TmpAdapterU ++;
	}
			
    AdapterNum = i;

	if(interfaz <1){
		for(i = 0 ; i < AdapterNum ; i++) 
		{
		 //wprintf(L"\n%d- %s\n", i + 1, AdapterList[i]); // ***
			 printf("\n%d- %s\n", i + 1, AdapterList[i]); 
		}
	}
	printf("\n");
  }		
  else {
// Windows 9X////////
					if(PacketGetAdapterNames((PTSTR)AdapterNameA, &AdapterLength) == FALSE) {
						 if(interfaz <1)  printf("Unable to retrieve the list of adapters!\n");

					  return(EXIT_FAILURE);
					}

					TmpAdapterA = AdapterNameA;
					AnotherTmpAdapterA = AdapterNameA;
							
					while((*TmpAdapterA != '\0') || (*(TmpAdapterA - 1) != '\0')) {
					  if(*TmpAdapterA == '\0') {				
						memcpy(AdapterList[i], AnotherTmpAdapterA, TmpAdapterA - AnotherTmpAdapterA);
						AdapterList[i][TmpAdapterA - AnotherTmpAdapterA] = '\0';
						AnotherTmpAdapterA = TmpAdapterA + 1;
						i++;
					  }
								
					  TmpAdapterA ++;
					}
							
					AdapterNum = i;

					for(i = 0 ; i < AdapterNum ; i++) {
					  if(interfaz <1) printf("\n%d- %s\n", i + 1, AdapterList[i]);				
					}
				  }
// FIN de Windows 9X ////


  //Se devuelve el nº de adaptador máximo si no le hemos indicado adaptador
  if(interfaz==33)return(AdapterNum);

  /* Select an adapter */

	    if(interfaz < 0)  return(EXIT_SUCCESS);	//si no se eligio interfaz ha mostrado las interfaces

		if( (interfaz > AdapterNum) || interfaz == 0 )	//si la interfaz es mayor que el numero total: error
		{
		  printf("\n**Numero de Interfaz erroneo**\n\n\t use -i para indicar el numero de interfaz\n\n\t use -a para ver las interfaces disponibles\n");
		  return(EXIT_FAILURE);
		}

      
  *lpAdapter =  PacketOpenAdapter(AdapterList[interfaz - 1]);

  if(!(*lpAdapter) || ((*lpAdapter)->hFile == INVALID_HANDLE_VALUE)) 
  {    
    fprintf(stderr, "\n\t*Error*  Interfaz erronea o winpcap 4.0 invalido o no instalado\n"); 
    return(EXIT_FAILURE);
  }

  return(EXIT_SUCCESS);
}


void close_adapter(LPADAPTER lpAdapter) 
{ 
  PacketCloseAdapter(lpAdapter);
}
