#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <ucontext.h>
#include <fcntl.h>
#include <asm/ldt.h>
#include <syscall.h>

#define STACK_ADDRESS (void *) 0x07000000
#define REGISTERS_TEMPLATE_ADDR (void *) 0x07005000
#define MAX_FILENAME_LEN 100
#define MAX_PHEADERS_NUM 200
#define MAX_NTFILE_NUM 100
#define MAX_NTFILE_FILENAMES_SIZE 3000

typedef void (*set_registers_fun) ();

unsigned char registers_template[] = {
    0xb8, 0x0, 0x0, 0x0, 0x0,       	// mov    $0, %eax
    0xbf, 0x0, 0x0, 0x0, 0x0,       	// mov    $0, %edi
    0xbe, 0x0, 0x0, 0x0, 0x0,       	// mov    $0, %esi
    0xba, 0x0, 0x0, 0x0, 0x0,       	// mov    $0, %edx
    0xb9, 0x0, 0x0, 0x0, 0x0,       	// mov    $0, %ecx
    0xbb, 0x0, 0x0, 0x0, 0x0,       	// mov    $0, %ebx
    0xbd, 0x0, 0x0, 0x0, 0x0,       	// mov    $0, %ebp
    0xbc, 0x0, 0x0, 0x0, 0x0,       	// mov    $0, %esp
    0x68, 0x0, 0x0, 0x0, 0x0,           // push   $0
    0x9d,                   	        // popf
    0x68, 0x0, 0x0, 0x0, 0x0,           // push   $0
    0xc3                   	            // ret
};

char filename[MAX_FILENAME_LEN];
ucontext_t context;

typedef struct {
    Elf32_Phdr headers[MAX_PHEADERS_NUM];
    Elf32_Phdr * note_header;
    int headers_num;
} program_headers_t;

typedef struct {
    int start;
    int end;
    int file_offset;
    char * filename;
} map_entry_t;

typedef struct {
    int map_entries;
    int page_size;
    map_entry_t entries[MAX_NTFILE_NUM];
    char _filenames[MAX_NTFILE_FILENAMES_SIZE];
} mapped_files_t;

// custom error
void cerror(const char * message) {
    write(STDERR_FILENO, message, strlen(message));
    exit(EXIT_FAILURE);
}

// system error
void serror(const char * message) {
    perror(message);
    exit(EXIT_FAILURE);
}

// wrappers
long wlseek(int fd, long offset, int whence) {
    long result;
    if ((result = lseek(fd, offset, whence)) == -1) {
        serror("Seek error");
    }
    return result;
}

long wread(int fd, void * buf, size_t size) {
    long bytes_read;
    if ((bytes_read = read(fd, buf, size)) == -1) {
        serror("Read error");
    }
    return bytes_read;
}

void * wmmap(void * addr, size_t size, int prot, int flags) {
    void * memory;
    if((memory = mmap(addr, size, prot, flags, -1, 0)) == MAP_FAILED) {
        serror("Mmap error");
    }
    return memory;
}

int wopen(char * filename) {
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        serror(filename);
    }
    return fd;
}

void wclose(int fd) {
    if (close(fd) == -1) {
        serror("Close error");
    }
}

unsigned int aligned(unsigned int size) {
    return size + ((sizeof(int) - (size % sizeof(int))) % sizeof(int));
}

void load_elf_header(int fd, Elf32_Ehdr * elf_header) {
    wread(fd, elf_header, sizeof(Elf32_Ehdr));
    if (elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
            elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
            elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
            elf_header->e_ident[EI_MAG3] != ELFMAG3) {
        cerror("Invalid elf magic number\n");
    }
    if (elf_header->e_type != ET_CORE) {
        cerror("Invalid elf type\n");
    }
}

void load_program_headers(int fd, Elf32_Ehdr * elf_header, program_headers_t * program_headers) {
    program_headers->headers_num = elf_header->e_phnum;
    wlseek(fd, elf_header->e_phoff, SEEK_SET);
    int i;
    for(i = 0; i < elf_header->e_phnum; ++i) {
        Elf32_Phdr * header = &program_headers->headers[i];
        wread(fd, header, sizeof(Elf32_Phdr));
        if (header->p_type == PT_NOTE) {
            program_headers->note_header = header;
        }
    }
}

void load_mapped_files(int fd, mapped_files_t * mapped_files, size_t data_size) {
    int i, bytes_read = 0;
    bytes_read += wread(fd, &mapped_files->map_entries, sizeof(int));
    bytes_read += wread(fd, &mapped_files->page_size, sizeof(int));
    for (i = 0; i < mapped_files->map_entries; ++i) {
        map_entry_t * entry = &mapped_files->entries[i];
        bytes_read += wread(fd, &entry->start, sizeof(int));
        bytes_read += wread(fd, &entry->end, sizeof(int));
        bytes_read += wread(fd, &entry->file_offset, sizeof(int));
    }
    size_t filenames_size = data_size - bytes_read;
    wread(fd, mapped_files->_filenames, filenames_size);
    char * curr = mapped_files->_filenames;
    for (i = 0; i < mapped_files->map_entries; ++i) {
        mapped_files->entries[i].filename = curr;
        while (*(curr++) != '\0');
    }
}

void load_note_data(int fd, program_headers_t *program_headers, struct elf_prstatus *prstatus,
                    struct user_desc * user_desc, mapped_files_t * mapped_files) {
    wlseek(fd, program_headers->note_header->p_offset, SEEK_SET);
    Elf32_Nhdr note_header;
    unsigned int bytes_read = 0;
    while (bytes_read != program_headers->note_header->p_filesz) {
        wread(fd, &note_header, sizeof(Elf32_Nhdr));
        unsigned int name_size = aligned(note_header.n_namesz);
        unsigned int data_size = aligned(note_header.n_descsz);
        wlseek(fd, name_size, SEEK_CUR);
        if (note_header.n_type == NT_PRSTATUS) {
            wread(fd, prstatus, sizeof(struct elf_prstatus));
        } else if (note_header.n_type == NT_386_TLS) {
            wread(fd, user_desc, sizeof(struct user_desc));
        } else if (note_header.n_type == NT_FILE) {
            load_mapped_files(fd, mapped_files, data_size);
        } else {
            wlseek(fd, data_size, SEEK_CUR);
        }
        bytes_read += (name_size + data_size + sizeof(Elf32_Nhdr));
    }
}

map_entry_t * find_mapped_file(Elf32_Phdr * header, mapped_files_t * mapped_files) {
    int i;
    for (i = 0; i < mapped_files->map_entries; i++) {
        if (mapped_files->entries[i].start == header->p_vaddr) {
            return &mapped_files->entries[i];
        }
    }
    return NULL;
}

void map_memory(int fd, program_headers_t *program_headers, mapped_files_t *mapped_files) {
    int i;
    Elf32_Phdr * header;
    for (i = 0; i < program_headers->headers_num; i++) {
        header = &program_headers->headers[i];
        if (header->p_type == PT_NOTE) {
            continue;
        }
        map_entry_t * found = find_mapped_file(header, mapped_files);
        void * memory = NULL;
        size_t size = 0;
        if (found != NULL) {
            int file = wopen(found->filename);
            size = (size_t) found->end - found->start;
            memory = wmmap((void *) header->p_vaddr, size,
                           PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS);
            wlseek(file, (found->file_offset) * mapped_files->page_size, SEEK_SET);
            wread(file, memory, size);
            wclose(file);
        } else {
            size = header->p_memsz;
            memory = wmmap((void *) header->p_vaddr, size, PROT_WRITE,
                           MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS);
        }
        if (header->p_filesz > 0) {
            wlseek(fd, header->p_offset, SEEK_SET);
            wread(fd, memory, header->p_filesz);
        }
        int prot = (header->p_flags & PF_R) ? PROT_READ : PROT_NONE;
        prot |= (header->p_flags & PF_W) ? PROT_WRITE : 0;
        prot |= (header->p_flags & PF_X) ? PROT_EXEC : 0;
        if (mprotect(memory, size, prot) == -1) {
            serror("Mprotect failed");
        }
    }
}

void copy_register_to_template(int template_offset, long int *reg) {
    memcpy(registers_template + template_offset, reg, sizeof(long int));
}

void set_registers(struct user_regs_struct * regs) {
    copy_register_to_template(1, &regs->eax);
    copy_register_to_template(6, &regs->edi);
    copy_register_to_template(11, &regs->esi);
    copy_register_to_template(16, &regs->edx);
    copy_register_to_template(21, &regs->ecx);
    copy_register_to_template(26, &regs->ebx);
    copy_register_to_template(31, &regs->ebp);
    copy_register_to_template(36, &regs->esp);
    copy_register_to_template(41, &regs->eflags);
    copy_register_to_template(47, &regs->eip);
    void * set_registers_addr = wmmap(REGISTERS_TEMPLATE_ADDR, (size_t) getpagesize(),
                                      PROT_READ | PROT_WRITE | PROT_EXEC,
                                      MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE);
    memcpy(set_registers_addr, registers_template, sizeof(registers_template));
    ((set_registers_fun) set_registers_addr)();
}

void load_core_dump() {
    Elf32_Ehdr elf_header;
    program_headers_t program_headers;
    mapped_files_t mapped_files;
    struct user_desc user_desc;
    struct elf_prstatus prstatus;

    int fd = wopen(filename);
    load_elf_header(fd, &elf_header);
    load_program_headers(fd, &elf_header, &program_headers);
    load_note_data(fd, &program_headers, &prstatus, &user_desc, &mapped_files);
    map_memory(fd, &program_headers, &mapped_files);
    wclose(fd);

    if (syscall(SYS_set_thread_area, &user_desc) == -1) {
        serror("Set thread area");
    }
    set_registers((struct user_regs_struct *) prstatus.pr_reg);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cerror("Usage: ./raise core_file\n");
    }
    strncpy(filename, argv[1], MAX_FILENAME_LEN);
    if (getcontext(&context) == -1) {
        serror("Getcontext error");
    }
    context.uc_stack.ss_sp = wmmap(STACK_ADDRESS, SIGSTKSZ,
                                   PROT_READ | PROT_WRITE | PROT_GROWSDOWN,
                                   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN);
    context.uc_stack.ss_size = SIGSTKSZ;
    context.uc_link = NULL;
    makecontext(&context, load_core_dump, 0);
    if (setcontext(&context) == -1) {
        serror("Setcontext error");
    }
    return 0;
}