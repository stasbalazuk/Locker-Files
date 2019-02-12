unit sts;

interface
{$I DEFINE.INC}

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  ComCtrls, StdCtrls, ExtCtrls, FilSecur, NTCommon, AbstrSec, ImgList,
  DetectWinOs;

type
  TFrmSecProperty = class(TForm)
    pclAccess: TPageControl;
    BtnClose: TButton;
    tbsAccessList: TTabSheet;
    tbsSystemAudit: TTabSheet;
    tbsOwnership: TTabSheet;
    pnlAccess: TPanel;
    gbxPermissions: TGroupBox;
    rbxFullPermission: TRadioButton;
    btnTakeOwnerShip: TButton;
    pnlOwner: TPanel;
    rbnOther: TRadioButton;
    lvUsers: TListView;
    grbFlags: TGroupBox;

    cbxObjectInherit: TCheckBox;
    cbxContainer: TCheckBox;
    cbxInheritOnly: TCheckBox;
    cbxNoPropogate: TCheckBox;
    cbxInherited: TCheckBox;

    cbxAppendData: TCheckBox;
    cbxChangePermission: TCheckBox;
    cbxDelete: TCheckBox;
    cbxDeleteChild: TCheckBox;
    cbxExecuteFile: TCheckBox;
    cbxOwnership: TCheckBox;
    cbxReadAttributes: TCheckBox;
    cbxReadData: TCheckBox;
    cbxReadExtAttributes: TCheckBox;
    cbxReadPermissions: TCheckBox;
    cbxSynchronize: TCheckBox;
    cbxWriteAttributes: TCheckBox;
    cbxWriteData: TCheckBox;
    cbxWriteExtAttributes: TCheckBox;

    cmbACEType: TComboBox;
    btnAdd: TButton;
    btnDelete: TButton;
    Label1: TLabel;
    imlUsers: TImageList;
    Bevel1: TBevel;
    cbxAutoInherit: TCheckBox;
    Button1: TButton;
    Button2: TButton;
    procedure pclAccessChange(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure btnTakeOwnerShipClick(Sender: TObject);
    procedure cbxAppendDataClick(Sender: TObject);
    procedure lvUsersChange(Sender: TObject; Item: TListItem;
      Change: TItemChange);
    procedure lvUsersEditing(Sender: TObject; Item: TListItem;
      var AllowEdit: Boolean);
    procedure lvUsersEdited(Sender: TObject; Item: TListItem;
      var S: String);
    procedure btnAddClick(Sender: TObject);
    procedure btnDeleteClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure cbxAutoInheritClick(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
  private
    { Private declarations }
    OldName: string;
    procedure SetCheckBoxState(AControl: TCheckBox; State: boolean);
    procedure SetRadioButtonState(AControl: TRadioButton; State: boolean);
    procedure SetEnabledControlState(AControl: TComponent; AEnabled: boolean);
    procedure SetButtonState(AEnabled: boolean);
    procedure SetAutoInheritance(AList: TAccessList; AEnabled: boolean);
    procedure FillcmbACEType;
 public
    { Public declarations }
    List: TAccessList;
    procedure RefreshInfo;
  end;

var
  FrmSecProperty: TFrmSecProperty;

implementation

{$R *.DFM}

Uses FrFileS, NT_vs_95;

function PrmissionsToStr(AMask: DWORD): string;
begin
  Result := '';
  if famRead and AMask <> 0 then Result := Result + 'R';
  if famWrite and AMask <> 0 then Result := Result + 'W';
  if famExecute and AMask <> 0 then Result := Result + 'X';
  if famDelete and AMask <> 0 then Result := Result + 'D';
  if famPermissions and AMask <> 0 then Result := Result + 'P';
  if famOwnership and AMask <> 0 then Result := Result + 'O';
  if famFullControl and AMask <> 0 then Result := 'F';
end;

function FlagsToStr(AFlags: TAceFlags): string;
begin
  Result := '';
  if acfObjInherit in AFlags then Result := Result + 'O';
  if acfContainer  in AFlags then Result := Result + 'C';
  if acfInheritOnly in AFlags then Result := Result + 'I';
  if acfNoPropagate in AFlags then Result := Result + 'N';
end;


procedure TFrmSecProperty.FillcmbACEType;
begin
  cmbACEType.Items.Clear;
  if pclAccess.ActivePage = tbsAccessList then
    begin
    cmbACEType.Items.AddObject('Access Allowed', TObject(Pointer(actAccessAllowed)));
    cmbACEType.Items.AddObject('Access Denied', TObject(Pointer(actAccessDenied)));
    end;
  if pclAccess.ActivePage = tbsSystemAudit then
    begin
    cmbACEType.Items.AddObject('Audit Success', TObject(Pointer(actAuditSuccess)));
    cmbACEType.Items.AddObject('Audit Failure', TObject(Pointer(actAuditFailure)));
    cmbACEType.Items.AddObject('Audit Full',    TObject(Pointer(actAuditFull)));
   end;
end;

procedure TFrmSecProperty.pclAccessChange(Sender: TObject);
begin
  if (pclAccess.ActivePage <> tbsOwnership) then
    pnlAccess.Parent  := pclAccess.ActivePage;
  FillcmbACEType;

  RefreshInfo;
end;

procedure TFrmSecProperty.RefreshInfo;
var
  i: integer;
begin
  List := nil;
  with FrmFileSecurity do
    begin
    if pclAccess.ActivePage = tbsAccessList   then
      begin
      List := FileSecurity.AccessList;
      SetCheckBoxState(cbxAutoInherit, FileSecurity.ControlWord and SE_DACL_PROTECTED = 0);
      end;

    if pclAccess.ActivePage = tbsSystemAudit  then
      try
        List := FileSecurity.SystemAudit;
        SetCheckBoxState(cbxAutoInherit, FileSecurity.ControlWord and SE_SACL_PROTECTED = 0);
      except
        List := nil;
      end;
    pnlOwner.Caption := FileSecurity.FileOwner;
    end;
    
  lvUsers.Items.Clear;
  if List <> nil then
    for i := 0 to List.Count - 1 do with lvUsers.Items.Add do
       begin
       Caption := List[i].UserName;
       case List[i].AceType of
         actAccessAllowed: StateIndex := 0;
         actAccessDenied: StateIndex := 1;
         actAuditSuccess: StateIndex := 2;
         actAuditFailure: StateIndex := 3;
         actAuditFull: StateIndex := 4;
       end; 
       end;

//  pnlAccess.Enabled := lvUsers.Items.Count > 0;


  SetRadioButtonState(rbxFullPermission, false);
  SetRadioButtonState(rbnOther, false);

  SetCheckBoxState(cbxAppendData, false);
  SetCheckBoxState(cbxChangePermission, false);
  SetCheckBoxState(cbxDelete, false);
  SetCheckBoxState(cbxDeleteChild, false);
  SetCheckBoxState(cbxExecuteFile, false);
  SetCheckBoxState(cbxOwnership, false);
  SetCheckBoxState(cbxReadAttributes, false);
  SetCheckBoxState(cbxReadData, false);
  SetCheckBoxState(cbxReadExtAttributes, false);
  SetCheckBoxState(cbxReadPermissions, false);
  SetCheckBoxState(cbxSynchronize, false);
  SetCheckBoxState(cbxWriteAttributes, false);
  SetCheckBoxState(cbxWriteData, false);
  SetCheckBoxState(cbxWriteExtAttributes, false);

  SetCheckBoxState(cbxObjectInherit, false);
  SetCheckBoxState(cbxContainer, false);
  SetCheckBoxState(cbxInheritOnly, false);
  SetCheckBoxState(cbxNoPropogate, false);
  SetCheckBoxState(cbxInherited, false);

  btnDelete.Enabled       := lvUsers.Items.Count > 0;
end;

procedure TFrmSecProperty.FormCreate(Sender: TObject);
begin
  cbxAutoInherit.Enabled := IsWindows2000;
  pclAccess.ActivePage := tbsAccessList;
  FillcmbACEType;
  RefreshInfo;
  Caption := FrmFileSecurity.FileSecurity.FileName;
  SetEnabledControlState(Self, not cbxAutoInherit.Checked);
end;

procedure TFrmSecProperty.btnTakeOwnerShipClick(Sender: TObject);
begin
  FrmFileSecurity.FileSecurity.TakeOwnership;
  RefreshInfo;
end;

procedure TFrmSecProperty.cbxAppendDataClick(Sender: TObject);
var
  AMask  : DWORD;
  AFlags : TAceFlags;
  index  : integer;
begin
  if (lvUsers.Selected = nil) or (List = nil) then Exit;
  AMask := 0;
  AFlags := [];

  if (Sender is TCheckBox) and (TCheckBox(Sender).Parent = gbxPermissions) then
    begin
    SetRadioButtonState(rbxFullPermission, false);
    SetRadioButtonState(rbnOther, true);
    end;

  if cbxAppendData.Checked           then AMask := AMask or famAppendData;
  if cbxChangePermission.Checked     then AMask := AMask or famChangePermissions;
  if cbxDelete.Checked               then AMask := AMask or famDelete;
  if cbxDeleteChild.Checked          then AMask := AMask or famDeleteChild;
  if cbxExecuteFile.Checked          then AMask := AMask or famExecuteFile;
  if cbxOwnership.Checked            then AMask := AMask or famOwnership;
  if cbxReadAttributes.Checked       then AMask := AMask or famReadAttr;
  if cbxReadData.Checked             then AMask := AMask or famReadData;
  if cbxReadExtAttributes.Checked    then AMask := AMask or famReadExtAttr;
  if cbxReadPermissions.Checked      then AMask := AMask or famReadPermissions;
  if cbxSynchronize.Checked          then AMask := AMask or famSynchronize;
  if cbxWriteAttributes.Checked      then AMask := AMask or famWriteAttr;
  if cbxWriteData.Checked            then AMask := AMask or famWriteData;
  if cbxWriteExtAttributes.Checked   then AMask := AMask or famWriteExtAttr;
  if rbxFullPermission.Checked       then AMask := AMask or famFullControl;

  if cbxObjectInherit.Checked then AFlags := AFlags + [acfObjInherit];
  if cbxContainer.Checked then AFlags := AFlags + [acfContainer];
  if cbxInheritOnly.Checked then AFlags := AFlags + [acfInheritOnly];
  if cbxNoPropogate.Checked then AFlags := AFlags + [acfNoPropagate];
  if cbxInherited.Checked then AFlags := AFlags + [acfInherited];


  index := lvUsers.Selected.Index;
  List.BeginUpdate;
  List[Index].Mask := AMask;
  List[Index].Flags := AFlags;
  List[Index].AceType := TAceType(integer(cmbACEType.Items.Objects[cmbACEType.ItemIndex]));
  List.EndUpdate;

  RefreshInfo;
  lvUsers.Selected := lvUsers.Items[Index];
end;

procedure TFrmSecProperty.lvUsersChange(Sender: TObject; Item: TListItem;
  Change: TItemChange);
var
  AMask:  DWORD;
  AFlags: TAceFlags;
  IsFullControl, IsInheritedACE: boolean;
  vAceType: DWORD;
  i: integer;
begin
  if Item = nil then Exit;
  if (lvUsers.Items.Count = 0) or (lvUsers.Selected = nil) then Exit;
  AMask    := List[lvUsers.Selected.Index].Mask;
  AFlags   := List[lvUsers.Selected.Index].Flags;
  vAceType := ord(List[lvUsers.Selected.Index].AceType);
  IsInheritedACE := acfInherited in AFlags;

  SetEnabledControlState(self, not IsInheritedACE);
  SetButtonState(not IsInheritedACE);

  IsFullControl := AMask = famFullControl;

  SetRadioButtonState(rbxFullPermission, IsFullControl);
  SetRadioButtonState(rbnOther, not IsFullControl);

  SetCheckBoxState(cbxAppendData,         (famAppendData and AMask = famAppendData) and not IsFullControl);
  SetCheckBoxState(cbxChangePermission,   (famChangePermissions and AMask = famChangePermissions) and not IsFullControl);
  SetCheckBoxState(cbxDelete,             (famDelete and AMask = famDelete) and not IsFullControl);
  SetCheckBoxState(cbxDeleteChild,        (famDeleteChild and AMask = famDeleteChild) and not IsFullControl);
  SetCheckBoxState(cbxExecuteFile,        (famExecuteFile and AMask = famExecuteFile) and not IsFullControl);
  SetCheckBoxState(cbxOwnership,          (famOwnership and AMask = famOwnership) and not IsFullControl);
  SetCheckBoxState(cbxReadAttributes,     (famReadAttr and AMask = famReadAttr) and not IsFullControl);
  SetCheckBoxState(cbxReadData,           (famReadData and AMask = famReadData) and not IsFullControl);
  SetCheckBoxState(cbxReadExtAttributes,  (famReadExtAttr and AMask = famReadExtAttr) and not IsFullControl);
  SetCheckBoxState(cbxReadPermissions,    (famReadPermissions and AMask = famReadPermissions) and not IsFullControl);
  SetCheckBoxState(cbxSynchronize,        (famSynchronize and AMask = famSynchronize) and not IsFullControl);
  SetCheckBoxState(cbxWriteAttributes,    (famWriteAttr and AMask = famWriteAttr) and not IsFullControl);
  SetCheckBoxState(cbxWriteData,          (famWriteData and AMask = famWriteData) and not IsFullControl);
  SetCheckBoxState(cbxWriteExtAttributes, (famWriteExtAttr and AMask = famWriteExtAttr) and not IsFullControl);


  SetCheckBoxState(cbxObjectInherit, acfObjInherit in AFlags);
  SetCheckBoxState(cbxContainer, acfContainer in AFlags);
  SetCheckBoxState(cbxInheritOnly, acfInheritOnly in AFlags);
  SetCheckBoxState(cbxNoPropogate, acfNoPropagate in AFlags);
  SetCheckBoxState(cbxInherited, acfInherited in AFlags);

  for i := 0 to cmbACEType.Items.Count - 1 do begin
    if DWORD(Pointer(cmbACEType.Items.Objects[i])) <> vAceType then
       cmbACEType.ItemIndex := i;
  end;
end;

  procedure TFrmSecProperty.SetCheckBoxState(AControl: TCheckBox; State: boolean);
var
  Event: TNotifyEvent;
begin
  Event := AControl.OnClick;
  AControl.OnClick := nil;
  AControl.Checked := State;
  AControl.OnClick := Event;
end;

  procedure TFrmSecProperty.SetRadioButtonState(AControl: TRadioButton; State: boolean);
var
  Event: TNotifyEvent;
begin
  Event := AControl.OnClick;
  AControl.OnClick := nil;
  AControl.Checked := State;
  AControl.OnClick := Event;
end;

procedure TFrmSecProperty.lvUsersEditing(Sender: TObject; Item: TListItem;
  var AllowEdit: Boolean);
begin
  AllowEdit := not cbxInherited.Checked;
  OldName := lvUsers.Selected.Caption;
end;

procedure TFrmSecProperty.lvUsersEdited(Sender: TObject; Item: TListItem;
  var S: String);
var
  index: integer;
begin
  index := lvUsers.Selected.Index;
  try
    List[Index].UserName := S;
    S := List[Index].UserName;
  except
    S := OldName; raise;
  end;

  //RefreshInfo;
end;


procedure TFrmSecProperty.btnAddClick(Sender: TObject);
var
  AUserName: string;
  vAceType:  TAceType;
begin
  if (List = nil) then Exit;
  if IsWindowsNT then AUserName := GetEveryOneName('') else
     AUserName := GetEveryOneName(FrmFileSecurity.FileSecurity.MachineName);

  if pclAccess.ActivePage = tbsSystemAudit then vAceType := actAuditFailure
    else vAceType := actAccessAllowed;

  List.Add(AUserName, 0, [], vAceType);
  RefreshInfo;
  lvUsers.Selected := lvUsers.Items[lvUsers.Items.Count - 1];
end;

procedure TFrmSecProperty.btnDeleteClick(Sender: TObject);
begin
  if (lvUsers.Items.Count = 0) or
     (lvUsers.Selected = nil) or
     (List = nil) then Exit;
  List.Delete(lvUsers.Selected.Index);
  RefreshInfo;
end;

procedure TFrmSecProperty.FormShow(Sender: TObject);
begin
  lvUsers.Columns[0].Width := lvUsers.ClientWidth;
end;

procedure TFrmSecProperty.SetAutoInheritance(AList: TAccessList; AEnabled: boolean);
var
  i: integer;
begin
// This procedure is a simplified version (for demo only) of how it should be;
// it sets or resets acfInherited flag;

// What it should do is:
// when setting autoinheritence, it should copy permissions from the
// parent object, with acfInherited flag cleared;
// when disabling autoinheritence, it should mark the existing ACEs as non-inherited;
// (as it works now)

  AList.BeginUpdate;
  try
    for i := 0 to AList.Count - 1 do
      if AEnabled then AList.Items[i].Flags := AList.Items[i].Flags + [acfInherited]
        else AList.Items[i].Flags := AList.Items[i].Flags - [acfInherited];
  finally
    AList.EndUpdate;
  end;
end;

procedure TFrmSecProperty.cbxAutoInheritClick(Sender: TObject);
var
  vControlWord: DWORD;
begin
// 1. Set the bit saying that DACL (SACL) (un)protected
  vControlWord := FrmFileSecurity.FileSecurity.ControlWord;

  if pclAccess.ActivePage = tbsAccessList   then
    begin
    if cbxAutoInherit.Checked then vControlWord := vControlWord and not SE_DACL_PROTECTED
      else vControlWord := vControlWord or SE_DACL_PROTECTED;
    FrmFileSecurity.FileSecurity.ControlWord := vControlWord;
    // if inherit permission - execute DoAutoPropogate
    // else - mark ACEs as not inherited
    if cbxAutoInherit.Checked then FrmFileSecurity.FileSecurity.DoAutoPropagateAccess
      else SetAutoInheritance(FrmFileSecurity.FileSecurity.AccessList, false);
    end;

  if pclAccess.ActivePage = tbsSystemAudit then
    begin
    if cbxAutoInherit.Checked then vControlWord := vControlWord and not SE_SACL_PROTECTED
      else vControlWord := vControlWord or SE_SACL_PROTECTED;
    FrmFileSecurity.FileSecurity.ControlWord := vControlWord;
    // if inherit permission - execute DoAutoPropogate
    // else - mark ACEs as not inherited
    if cbxAutoInherit.Checked then FrmFileSecurity.FileSecurity.DoAutoPropagateAudit
      else SetAutoInheritance(FrmFileSecurity.FileSecurity.SystemAudit, false);
    end;

  RefreshInfo;
end;

procedure TFrmSecProperty.SetEnabledControlState(AControl: TComponent; AEnabled: boolean);
var
  i: integer;
begin
  if (AControl = cbxAutoInherit) or (AControl = cbxInherited) then Exit;
  if (AControl is TCheckBox) then (AControl as TCheckBox).Enabled :=  AEnabled;
  if (AControl is TRadioButton) then (AControl as TRadioButton).Enabled :=  AEnabled;
  if (AControl is TComboBox) then (AControl as TComboBox).Enabled :=  AEnabled;
  if AControl is TControl then
    for i := 0 to AControl.ComponentCount - 1 do
      SetEnabledControlState(AControl.Components[i], AEnabled);
end;

procedure TFrmSecProperty.SetButtonState(AEnabled: boolean);
begin
  btnDelete.Enabled := AEnabled;
end;

procedure TFrmSecProperty.Button1Click(Sender: TObject);
var
  AMask  : DWORD;
  AFlags : TAceFlags;
  index  : integer;
begin
  index := 0;
  AMask := AMask or famFullControl;
  List.BeginUpdate;
  List[Index].Mask := AMask;
  List[Index].Flags := AFlags;  //cmbACEType.Items.Objects[cmbACEType.ItemIndex]
  List[Index].AceType := TAceType(integer(1));
  List.EndUpdate;
  RefreshInfo;
  lvUsers.Selected := lvUsers.Items[Index];
end;

procedure TFrmSecProperty.Button2Click(Sender: TObject);
var
  AMask  : DWORD;
  AFlags : TAceFlags;
  index  : integer;
begin
  index := 0;
  AMask := AMask or famFullControl;
  List.BeginUpdate;
  List[Index].Mask := AMask;
  List[Index].Flags := AFlags;  //cmbACEType.Items.Objects[cmbACEType.ItemIndex]
  List[Index].AceType := TAceType(integer(0));
  List.EndUpdate;
  RefreshInfo;
  lvUsers.Selected := lvUsers.Items[Index];
end;

end.
