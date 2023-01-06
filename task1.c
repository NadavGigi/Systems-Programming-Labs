#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>
typedef struct {
    char *name;
    void (*fun)();
}fun_desc;
int debug=0;
//global vars
Elf32_Ehdr* header;
Elf32_Shdr* sections;
Elf32_Sym* dynsym = 0;
Elf32_Sym* symtab = 0;
char* dynsymNames;
char* symtabNames;
int dynsymSize = 0;
int symtabSize = 0;
Elf32_Rel* reldym = 0;
Elf32_Rel* relplt = 0;
int reldymSize = 0;
int relpltSize = 0;
char* sectionsNames ;
void* address;
void toggleDebugMode(){
    if(debug)
        printf("Debug flag now off\n");
    else
        printf("Debug flag now on\n");
    debug= !debug;
}
void ExamineELFFile(){
    char buffer[100];
    char fileName[100];
    printf("Enter file name:\n");
    fscanf(stdin,"%s",fileName);
//    sscanf(buffer, "%s\n", fileName);
    int fd = open(fileName, O_RDONLY);
    if(fd < 0){
        perror("open");
        exit(0);
    }
    int size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    address = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    if(address == MAP_FAILED){
        perror("mmap");
        exit(0);
    }
    header = (Elf32_Ehdr*) address;
    sections = (Elf32_Shdr*) (address + header->e_shoff);
    sectionsNames = (char*)(address + sections[header->e_shstrndx].sh_offset);
    if(header->e_ident[0] == 0x7f && header->e_ident[1] == 0x45 && header->e_ident[2] == 0x4C && header->e_ident[3] == 0x46){
        printf("ELF Header:\n");
        printf("Magic:   %X %X %X %X\n", header->e_ident[0], header->e_ident[1],header->e_ident[2],header->e_ident[3]);
        if(header->e_ident[EI_DATA] == ELFDATA2LSB)
            printf("2's complement, little endian\n");
        else
            printf("2's complement, big endian\n");
        for(int i = 0; i < header->e_shnum; i++){
            if(strcmp(sectionsNames + sections[i].sh_name, ".dynsym") == 0){
                dynsym = (Elf32_Sym*) (address + sections[i].sh_offset);
                dynsymSize = sections[i].sh_size/sections[i].sh_entsize;
            }
            if(strcmp(sectionsNames + sections[i].sh_name, ".symtab") == 0){
                symtab = (Elf32_Sym*) (address + sections[i].sh_offset);
                symtabSize= sections[i].sh_size/sections[i].sh_entsize;
            }
            if(strcmp(sectionsNames + sections[i].sh_name, ".strtab") == 0){
                symtabNames = (char*) (address + sections[i].sh_offset);
            }
            if(strcmp(sectionsNames + sections[i].sh_name, ".dynstr") == 0){
                dynsymNames = (char*) (address + sections[i].sh_offset);
            }
            if(strcmp(sectionsNames + sections[i].sh_name, ".rel.dyn") == 0){
                reldym = (Elf32_Rel*) (address + sections[i].sh_offset);
                reldymSize = sections[i].sh_size/sections[i].sh_entsize;
            }
            if(strcmp(sectionsNames + sections[i].sh_name, ".rel.plt") == 0){
                relplt = (Elf32_Rel*) (address + sections[i].sh_offset);
                relpltSize = sections[i].sh_size/sections[i].sh_entsize;
            }
        }
        printf("Enty point address:\t\t 0x%x\n",header->e_entry);
        printf("Start of section headers:\t %d (bytes into file)\n",header->e_shoff);
        printf("Number of section headers:\t %d\n",header->e_shnum);
        printf("Size of section headers:\t %d (bytes)\n",header->e_shentsize);
        printf("Start of program headers:\t %d (bytes into file)\n",header->e_phoff);
        printf("Number of program headers:\t %d\n",header->e_phnum);
        printf("Size of program headers:\t %d (bytes)\n",header->e_phentsize);
    }    else{
        printf("This is not ELF file\n");
        munmap(address, size);
        close(fd);
    }
}

void PrintSectionNames() {
    if(debug){
        Elf32_Shdr* sections_table = address+header->e_shoff;
        Elf32_Shdr* string_table_entry = address+header->e_shoff+(header->e_shstrndx*header->e_shentsize);
        printf("section table address: %p\n",sections_table);
        printf("string table entry: %p\n",string_table_entry);
    }
    printf("There are %d section headers, starting at offset %#x:\n"
            ,header->e_shnum,header->e_shoff);
    printf("\nSection Headers:\n");
    printf("[NR] Name                 Addr     Off    Size   Type\n");
    for(int index=0;index< header->e_shnum;index++){
        printf("[%2d] %-20s %08x %06x %06x %#x\n",index,
               sectionsNames + sections[index].sh_name,
               sections[index].sh_addr, sections[index].sh_offset,
               sections[index].sh_size, sections[index].sh_type);
    }

}
void PrintSymbols(){
    printf("Symbol table '.dynsym' contains %d entries:\n", dynsymSize);
    printf("[NR] Value\tNdx      SectionName     \tSymbolName\n");
    for(int i = 0; i < dynsymSize; i++){
        char* sectionName;
        if(dynsym[i].st_shndx==0)
            sectionName ="UND";
        else if(dynsym[i].st_shndx == 65521)
            sectionName ="ABS";
        else if(dynsym[i].st_shndx<header->e_shnum)
            sectionName = (char*)(address+sections[header->e_shstrndx].sh_offset)+sections[dynsym[i].st_shndx].sh_name;
        else
            sectionName = "COM";
//        printf("%d) %s\n", i, dynsymNames+dynsym[i].st_name);
        printf("[%2d] %08x\t%-6d\t %-18.18s\t %s\n",i ,dynsym[i].st_value, dynsym[i].st_shndx,sectionName,dynsymNames+dynsym[i].st_name);

    }
    printf("Symbol table '.symtab' contains %d entries:\n", symtabSize);
    printf("[NR] Value\tNdx      SectionName     \tSymbolName\n");
    for(int i = 0; i < symtabSize; i++){
        char* sectionName;
        if(symtab[i].st_shndx==0)
            sectionName ="UND";
        else if(symtab[i].st_shndx == 65521)
            sectionName ="ABS";
        else if(symtab[i].st_shndx<header->e_shnum)
            sectionName = (char*)(address+sections[header->e_shstrndx].sh_offset)+sections[symtab[i].st_shndx].sh_name;
        else
            sectionName = "COM";
//        printf("%d) %s\n", i, dynsymNames+symtab[i].st_name);
        printf("[%2d] %08x\t%-6d\t %-18s\t %s\n",i ,
               symtab[i].st_value, symtab[i].st_shndx,
               sectionName,symtabNames+symtab[i].st_name);
    }
    }

void quit(){
    if (debug==1)
        printf("quitting\n");
    exit(0);
}
void RelocationTables(){
    printf("Relocation section '.rel.dyn' at offset %d contains %d entry:\n", ((char*)reldym-(char*)address), reldymSize);
    printf("Offset\t\tInfo\t\tType\t\tSym.value\t\tSym.name\n");
    for(int i = 0; i < reldymSize; i++){
        printf("%08x\t%08d\t%-8d\t%08d\t\t%s\n",reldym[i].r_offset,reldym[i].r_info ,ELF32_R_SYM(reldym[i].r_info),dynsym[ELF32_R_SYM(reldym[i].r_info)], dynsymNames+dynsym[ELF32_R_SYM(reldym[i].r_info)].st_name);
    }
    printf("Relocation section '.rel.plt' at offset %d contains %d entry:\n", ((char*)relplt-(char*)address), relpltSize);
    printf("Offset\t\tInfo\t\tType\t\tSym.value\t\tSym.name\n");

    for(int i = 0; i < relpltSize; i++){
        printf("%08x\t%08d\t%-8d\t%08d\t\t%s\n",relplt[i].r_offset,relplt[i].r_info ,ELF32_R_SYM(relplt[i].r_info),
               dynsym[ELF32_R_SYM(relplt[i].r_info)], dynsymNames+dynsym[ELF32_R_SYM(relplt[i].r_info)].st_name);
    }
}



fun_desc menu[] = {{"Toggle Debug Mode",   toggleDebugMode },
                   {"Examine ELF File",    ExamineELFFile },
                   {"Print Section Names", PrintSectionNames },
                   {"Print Symbols",       PrintSymbols },
                   {"Relocation Tables",   RelocationTables },
                   {"Quit",                quit } , { NULL, NULL } };
void printMenu() {
    fprintf(stdout, "   Choose Action:\n");

    int i=0 ;
    while(menu[i].name != NULL) {
        fprintf(stdout, "%d) %s\n", i, menu[i].name);
        i++;
    }

    fprintf(stdout, "Option: ");

}
int main(int argc, char **argv){
    while(1){
        if (debug){
        }
        printMenu();
        //getting input fron the user
        int option;
        scanf("%d", &option);

        if (option >= 0 && option < 10){
            fprintf(stdout, "Within bounds\n" );
        }
        else{
            fprintf(stdout, "Not within bounds\n" );
            //exit (0);
            return -1;
        }
        menu[option].fun();

    }
    return 0;
}
