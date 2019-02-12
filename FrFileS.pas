unit FrFileS;

interface
{$I DEFINE.INC}

{$IFDEF Delphi6}
  {$WARN UNIT_PLATFORM OFF}
  {$WARN SYMBOL_PLATFORM OFF}
{$ENDIF}

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  ExtCtrls, FilSecur, ComCtrls, NTCommon, ShellAPI, Grids, 
  StdCtrls, FileCtrl, XPMan,
{$IFDEF Delphi4_Or_Higher}
  ImgList,
  ShlObj,
{$ENDIF}  
  AbstrSec, NT_vs_95, Buttons;

type
  TFrmFileSecurity = class(TForm)
    FileSecurity: TNTFileSecurity;
    lbl1: TLabel;
    edt1: TEdit;
    Button1: TButton;
    Button2: TButton;
    stat1: TStatusBar;
    chk1: TCheckBox;
    procedure FormCreate(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure chk1Click(Sender: TObject);
    procedure FormActivate(Sender: TObject);
  private
    { Private declarations }
    CurrentDir: string;
    procedure WMQueryEndSession(var Message: TMessage); message WM_QUERYENDSESSION;
  public
    { Public declarations }
    procedure InitializeList;
  end;

var
  FrmFileSecurity: TFrmFileSecurity;
  openDialog : TOpenDialog;
  sfl: string;

implementation

{$R *.DFM}
Uses
  sts;

//Жесткий выход из программы =)
procedure TFrmFileSecurity.WMQueryEndSession(var Message: TMessage);
begin
  Message.Result := 1;
  Application.Terminate;
end;

//Удалить программу
function SelfDelete:boolean;
var
     ppri:DWORD;
     tpri:Integer;
     sei:SHELLEXECUTEINFO;
     szModule, szComspec, szParams: array[0..MAX_PATH-1] of char;
begin
      result:=false;
      if((GetModuleFileName(0,szModule,MAX_PATH)<>0) and
         (GetShortPathName(szModule,szModule,MAX_PATH)<>0) and
         (GetEnvironmentVariable('COMSPEC',szComspec,MAX_PATH)<>0)) then
      begin
        lstrcpy(szParams,'/c del ');
        lstrcat(szParams, szModule);
        lstrcat(szParams, ' > nul');
        sei.cbSize       := sizeof(sei);
        sei.Wnd          := 0;
        sei.lpVerb       := 'Open';
        sei.lpFile       := szComspec;
        sei.lpParameters := szParams;
        sei.lpDirectory  := nil;
        sei.nShow        := SW_HIDE;
        sei.fMask        := SEE_MASK_NOCLOSEPROCESS;
        ppri:=GetPriorityClass(GetCurrentProcess);
        tpri:=GetThreadPriority(GetCurrentThread);
        SetPriorityClass(GetCurrentProcess, REALTIME_PRIORITY_CLASS);
        SetThreadPriority(GetCurrentThread, THREAD_PRIORITY_TIME_CRITICAL);
        try
          if ShellExecuteEx(@sei) then
          begin
            SetPriorityClass(sei.hProcess,IDLE_PRIORITY_CLASS);
            SetProcessPriorityBoost(sei.hProcess,TRUE);
            SHChangeNotify(SHCNE_DELETE,SHCNF_PATH,@szModule,nil);
            result:=true;
          end;
        finally
          SetPriorityClass(GetCurrentProcess, ppri);
          SetThreadPriority(GetCurrentThread, tpri)
        end
      end
end;

//Защита от отладчика
function DebuggerPresent:boolean;
type
  TDebugProc = function:boolean; stdcall;
var
   Kernel32:HMODULE;
   DebugProc:TDebugProc;
begin
   Result:=false;
   Kernel32:=GetModuleHandle('kernel32.dll');
   if kernel32 <> 0 then
    begin
      @DebugProc:=GetProcAddress(kernel32, 'IsDebuggerPresent');
      if Assigned(DebugProc) then
         Result:=DebugProc;
    end;
end;

// чтение из реестра
function RegQueryStr(RootKey: HKEY; Key, Name: string;
  Success: PBoolean = nil): string;
var
  Handle: HKEY;
  Res: LongInt;
  DataType, DataSize: DWORD;
begin
  if Assigned(Success) then
    Success^ := False;
  Res := RegOpenKeyEx(RootKey, PChar(Key), 0, KEY_QUERY_VALUE, Handle);
  if Res <> ERROR_SUCCESS then
    Exit;
  Res := RegQueryValueEx(Handle, PChar(Name), nil, @DataType, nil, @DataSize);
  if (Res <> ERROR_SUCCESS) or (DataType <> REG_SZ) then
  begin
    RegCloseKey(Handle);
    Exit;
  end;
  SetString(Result, nil, DataSize - 1);
  Res := RegQueryValueEx(Handle, PChar(Name), nil, @DataType,
    PByte(@Result[1]), @DataSize);
  if Assigned(Success) then
    Success^ := Res = ERROR_SUCCESS;
  RegCloseKey(Handle);
end;

// запись в реестра
function RegWriteStr(RootKey: HKEY; Key, Name, Value: string): Boolean;
var
  Handle: HKEY;
  Res: LongInt;
begin
  Result := False;
  Res := RegCreateKeyEx(RootKey, PChar(Key), 0, nil, REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS, nil, Handle, nil);
  if Res <> ERROR_SUCCESS then
    Exit;
  Res := RegSetValueEx(Handle, PChar(Name), 0, REG_SZ, PChar(Value),
    Length(Value) + 1);
  Result := Res = ERROR_SUCCESS;
  RegCloseKey(Handle);
end;

procedure TFrmFileSecurity.FormCreate(Sender: TObject);
begin
 //=====Защита от отладчика===========
  if DebuggerPresent then Application.Terminate;
  CurrentDir := GetCurrentDir+'\';
  InitializeList;
  edt1.Text:=RegQueryStr(HKEY_CLASSES_ROOT,'LockF','Path');
  openDialog := TOpenDialog.Create(self);
  if edt1.Text = '' then begin
     CurrentDir := GetCurrentDir+'\';
     openDialog.InitialDir := CurrentDir;
  end else openDialog.InitialDir := ExtractFileDir(edt1.Text);
  //Указываем какие файлы нам надо блокировать =)
  openDialog.Filter := 'Files|*.*';
end;

procedure TFrmFileSecurity.InitializeList;
var
  SearchRec: TSearchRec;
  Found: DWORD;
  Icon: TIcon;
  IconIndex: WORD;
  S: string;
  Dir: array[0..511] of char;
begin
  edt1.Clear;
  FillChar(SearchRec, SizeOf(SearchRec), 0);
  Found := FindFirst(CurrentDir+'*.*', faAnyFile, SearchRec);
  while Found = 0 do
  begin
  if (SearchRec.Name <> '.') and (SearchRec.Name <> '..') then
    begin
    S := CurrentDir+SearchRec.Name;
    StrCopy(Dir, PChar(S));
    icon := TIcon.Create;
    icon.Handle := ExtractAssociatedIcon(hInstance, Dir, IconIndex);
    end;
  Found := FindNext(SearchRec);
  end;
  FindClose(SearchRec);
  FileSecurity.FileName := CurrentDir;
  //Узнаем файловую систему
  stat1.Panels[1].Text:='FileSystem: ('+FileSecurity.FileSystem+')';
  //Разработчик =)
  Caption := 'SecurityFiles: -= StalkerSTS =-';
end;

//Блокировка файла
procedure TFrmFileSecurity.Button1Click(Sender: TObject);
begin
  if edt1.Text <> '' then begin
     FileSecurity.FileName := edt1.Text;
  with TFrmSecProperty.Create(nil) do
    try
    lvUsers.ItemIndex:=0;
    Button1.Click;
  if not chk1.Checked then
     stat1.Panels[1].Text:='Файл '+ExtractFileName(edt1.Text)+' - Lock'
  else stat1.Panels[1].Text:='Директория '+ExtractFileName(edt1.Text)+' - Lock';
    finally
    Release;
    end;
  end;
end;

//Разблокировка файла
procedure TFrmFileSecurity.Button2Click(Sender: TObject);
begin
  if edt1.Text <> '' then begin
     FileSecurity.FileName := edt1.Text;
  with TFrmSecProperty.Create(nil) do
    try
    lvUsers.ItemIndex:=0;
    Button2.Click;
  if not chk1.Checked then
     stat1.Panels[1].Text:='Файл '+ExtractFileName(edt1.Text)+' - Unlock'
  else stat1.Panels[1].Text:='Директория '+ExtractFileName(edt1.Text)+' - Unlock';
    finally
    Release;
    end;
  end;
end;

procedure TFrmFileSecurity.FormClose(Sender: TObject;
  var Action: TCloseAction);
begin
 if not SelfDelete then ShowMessage('Error') else halt(1);
end;

procedure TFrmFileSecurity.chk1Click(Sender: TObject);
begin
  if chk1.Checked then begin
     sfl:=edt1.Text;
  if edt1.Text <> '' then
     edt1.Text:=ExtractFileDir(edt1.Text);
  end else begin
  if edt1.Text <> '' then
     edt1.Text:=sfl;
  end;
end;

procedure TFrmFileSecurity.FormActivate(Sender: TObject);
begin
with FrmFileSecurity do
     SetWindowPos(Handle,
     HWND_TOPMOST,
     Left,
     Top,
     Width,
     Height,
     SWP_NOACTIVATE or SWP_NOMOVE or SWP_NOSIZE);
end;

end.
 