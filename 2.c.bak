#include <stdio.h>
#include <stdlib.h>
//#include <winnt.h>

long filesize(FILE *pFile)
{
 long lSize;
 fseek (pFile , 0 , SEEK_END);
 lSize=ftell (pFile);
 rewind (pFile);
 return lSize;
}
typedef unsigned short WORD;
typedef long           LONG;
typedef unsigned char  BYTE;
typedef unsigned long DWORD;

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_NT_SIGNATURE 0x00004550

typedef struct _IMAGE_DOS_HEADER {
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY,*PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	DWORD BaseOfData;
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Reserved1;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER,*PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS,*PIMAGE_NT_HEADERS;

         
int main(int argc, char *argv[])
{
  IMAGE_DOS_HEADER myDosHeader;
  IMAGE_OPTIONAL_HEADER myOptionalHeader;
  IMAGE_FILE_HEADER myFileHeader;
  IMAGE_NT_HEADERS	 stPEHeader;
  DWORD petag;
  WORD dlltag,systag,t;
  LONG e_lfanew;
  FILE *pFile,*pMain,*pOverlay;
  if(!(pFile = fopen(argv[1], "rb")))
  {
           printf ("error: File Not Found\n");
           return 0;
           }

  fread(&myDosHeader, sizeof(IMAGE_DOS_HEADER), 1, pFile);
  if(myDosHeader.e_magic!=IMAGE_DOS_SIGNATURE)
  {
   printf("error: not a MZ\n");                                            
   return 0;
   }else
   {
  e_lfanew = myDosHeader.e_lfanew;
}
   fseek(pFile,e_lfanew,SEEK_SET);
   fread(&petag,sizeof(DWORD),1,pFile);
   if(petag!=IMAGE_NT_SIGNATURE)//"PE\0\0"
  {
     printf("error: not a PE\n");
    return;
  }else
  {
    //printf("PE ok\n");
  }


    fseek(pFile, (e_lfanew + sizeof(DWORD)), SEEK_SET);
    fread(&myFileHeader, sizeof(IMAGE_FILE_HEADER), 1, pFile);
    
    dlltag=myFileHeader.Characteristics;
    
    fseek(pFile, (e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)), SEEK_SET);     // 如此定位的原因请参考PE文件结构图
    fread(&myOptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER), 1, pFile);

    systag=myOptionalHeader.Subsystem;

    //printf("%04x\n",myFileHeader.Characteristics);
    //printf("%04x\n",myOptionalHeader.Subsystem);
    
    t=dlltag&0xF000;
    //printf("%04x\n",t);
    if(systag==1)
    {
      printf("system file\n");
    }
    if(t==0x2000)
    {
      printf("dll file\n");
    }

  fclose(pFile);
  return 0;
}
